require 'eventmachine'
require 'xmpp4r/client'
require 'yaml'
include Jabber

puts "-> GtalkBot class loaded!"

class GtalkBot

  #--------------------------------------------
  # Initialize function
  #--------------------------------------------
  def initialize()
    puts "-> Initialize GtalkBot method called!"
    
    # get configurations from config.yml file
    tree = YAML::parse( File.open( "config.yml" ) )
    obj_tree = tree.transform
    yml_un=obj_tree['username']
    yml_pw=obj_tree['password']
    yml_dn=obj_tree['devicename']
    yml_to=obj_tree['target']
    
    # defines message target address
    @target_account = yml_to

    # initialize variable for the array of strings
    @stringlist = [""]

    # initialize @callbacks object
    @callbacks = {}
    initialize_callbacks()

    #Jabber::debug=true
    jid = JID::new(yml_un+'/'+yml_dn)
    password = yml_pw
    @cl = Client::new(jid)
    @cl.connect
    @cl.auth(password)
    @cl.send(Presence.new.set_type(:available)) 

    # Add a message callback to respond to peer requests
    @cl.add_message_callback do |inmsg|
      puts "Received Message: "+inmsg.body 
      #self.sendmessage("You have sent me this message: #{inmsg.body}")

      # adding message to string array
      @stringlist = inmsg.body.split(' ')
      
      #puts "Printing CMD array:"
      #puts @stringlist.inspect
      exec_cmd(@stringlist)
    end
  end

  #------------------------------------
  # function to send xmpp reply message
  #------------------------------------
  def sendmessage(text)
    to = @target_account
    subject = "XMPP4R test"
    body = text
    message = Message::new(to, body).set_type(:chat).set_id('1').set_subject(subject)
    @cl.send message
  end

  #-----------------------------------------------
  # function to add callbacks to @callbacks object
  #-----------------------------------------------
  def add_callback(name, &callback)
    name = name.to_s
    @callbacks[name] = callback
    self
  end

  #------------------------------------------------------------
  # function to run callbacks from @callback object (if exists)
  #------------------------------------------------------------
  def run_callback(name, *args)
    name = name.to_s
    @callbacks[name].call(*args) if @callbacks[name]
  end

  #--------------------------------------------------------------
  # function called to execute a remote command (initial parsing)
  #--------------------------------------------------------------
  def exec_cmd(params)

    #puts params.inspect

    @callbacks.each do |name, callback|
      if params[0].eql?(name) == true
        callback.call(params)
        return
      end
    end
    puts "--> NO CMD FOUND!"
  end

  #-------------------------------------------------------------
  # Initialize Callbacks - to be customized
  #-------------------------------------------------------------
  def initialize_callbacks

    # help
    add_callback(:help) do |arg|
      commandlist()
    end

    # exit
    add_callback(:exit) do |arg|
      finalize()
    end

    # quit
    add_callback(:quit) do |arg|
      finalize()
    end

    # Gtalk Status Ready
    add_callback(:ready) do |arg|
      SetStatusReady()
    end

    # Gtalk Status Do Not Disturb
    add_callback(:busy) do |arg|
      SetStatusDND()
    end

    # ...
    #add_callback(:dir) do |arg|
    #  puts arg.inspect
    #  if(arg[1] == nil)
    #    arg[1] = "/home"
    #  end
    #  Dir.chdir arg[1] # need to escape path from malicious ;rm -rf injection
    #  result = %x(ls -la)
    #  sendmessage(">ls -la #{arg[1]}\r\n#{result}")     
    #  puts result
    #end

    # Network
    add_callback(:network) do |arg|
      ethernet_interfaces()
    end
  
    # List system active users
    add_callback(:active_users) do |arg|
      active_users()
    end   

    # File System Usage
    add_callback(:file_system_usage) do |arg|
      file_system_usage()
    end

    # Processes Memory
    add_callback(:proc_mem) do |arg|
      processes_using_most_memory()
    end

    # Processes Cpu
    add_callback(:proc_cpu) do |arg|
       processes_using_most_cpu()
    end

    add_callback(:proc_zombie) do |arg|
      zombie_processes()
    end

    #add_callback(:tcp_sockets_listen) do |arg|
    #  listening_tcp_sockets()
    #end

    #add_callback(:tcp_sockets_connected) do |arg|
    #  connected_tcp_sockets()
    #end
  end

  #-------------------------------------------------------------
  # other auxiliar functions
  #--------------------------------------------------------------

  #--------------------------------------------------------------
  # List Callback Commands
  def commandlist()
     sendmessage("Available commands:")
     @callbacks.each do |name|
        str = "#{name[0]}"
        puts "--> "+str
        sendmessage(str)
      end
  end  
  #--------------------------------------------------------------
  # Gtalk Status Ready
  def SetStatusReady()
    @cl.send(Presence.new.set_type(:available)) 
  end
  #--------------------------------------------------------------
  # Gtalk Status Do Not Disturb
  def SetStatusDND()
    @cl.send(Jabber::Presence.new.set_show(:dnd))
  end
  #--------------------------------------------------------------
  # Exit Application
  def finalize()
    puts "-> Finalize GtalkBot method called"
    #@cl.close
    EM.stop
    return
  end
  #--------------------------------------------------------------
  # File System Usage
  def file_system_usage
    fs_type_result = `df -T`
    fsystem = ['hfs', 'ext4', 'ext3', 'ext', 'ext2'].select{|fst| /\s#{fst}\s/.match(fs_type_result)}.inject([]) do |result, fst|
      `df --type=#{fst} -H`.split("\n")[1..-1].each do |row|
        vals = row.split(/\s+/)       
        mount = vals[5..-1].join(" ")
        size = vals[1]
        used = vals[4]
        str = "#{mount} | #{size} | #{used}"
        puts "--> "+str
        sendmessage(str)
      end
    end
  end
  #--------------------------------------------------------------
  # Ethernet Interfaces configuration
  def ethernet_interfaces
    ifaces = /(eth\d)/.match(`ifconfig -a`).captures.inject([]) do |result, iface|
      ifconfig = `ifconfig #{iface}`
      ip = /inet\saddr:(\d+\.\d+\.\d+\.\d+)/.match(ifconfig).captures.last
      mac = /HWaddr\s(\w+\:\w+\:\w+\:\w+\:\w+\:\w+)/.match(ifconfig).captures.last
      str = "ip: #{ip} | mac: #{mac}"
      puts "--> "+str
      sendmessage(str)
    end
  end
  #--------------------------------------------------------------
  def active_users
    users =`who`.split("\n").collect do |user|
      user_data = user.strip.split(/\s+/)
      ip = /\((.*)\)/.match(user_data.last).captures.last
      active_since = user_data[2] + ' ' + user_data[3]
      str = "[#{user_data[0]}] user active since [#{active_since}] from ip [#{ip}]"
      puts "--> "+str
      sendmessage(str)
    end
  end
  #--------------------------------------------------------------
  def processes_using_most_memory
    procs = `ps -eo pid,pcpu,pmem,comm`.split("\n")[1..-1].collect do |p|
      p_data = p.strip.split(/\s+/)
      {:pid => p_data[0], :command => p_data[3], :cpu => p_data[1].to_f, :memory => p_data[2].to_f}
    end
    largest_items_by_attribute(procs, :memory)

    for i in 1..10 do
      str = "pid="+procs[i][:pid]+
            " | cmd="+procs[i][:command]+
            " | cpu="+procs[i][:cpu].to_s+
            " | mem="+procs[i][:memory].to_s
      puts "--> "+str
      sendmessage(str)
    end
  end
  #--------------------------------------------------------------
  def processes_using_most_cpu
    procs = `ps -eo pid,pcpu,pmem,comm`.split("\n")[1..-1].collect do |p|
      p_data = p.strip.split(/\s+/)
      {:pid => p_data[0], :command => p_data[3], :cpu => p_data[1].to_f, :memory => p_data[2].to_f}
    end
    largest_items_by_attribute(procs, :cpu)

    for i in 1..10 do
      str = "pid="+procs[i][:pid]+
            " | cmd="+procs[i][:command]+
            " | cpu="+procs[i][:cpu].to_s+
            " | mem="+procs[i][:memory].to_s
      puts "--> "+str
      sendmessage(str)
    end

  end
  #--------------------------------------------------------------
  def largest_items_by_attribute(items, by_attr)
    largest_items = items.sort_by {|i| -i[by_attr]}
    largest_items = largest_items[0..4] if largest_items.count > 5
    largest_items.count.eql?(1) ? largest_items.first : largest_items
  end
  #--------------------------------------------------------------
  def zombie_processes
    procs = `ps -eo pid,pcpu,pmem,state,comm`.split("\n")[1..-1].inject({}) do |result, p|
      p_data = p.strip.split(/\s+/)
      if (p_data[3].eql?('Z'))
        str = "pid="+p_data[0]+
              " | cmd="+p_data[4]+
              " | cpu="+ p_data[1]+
              " | mem="+ p_data[2]
        puts "--> "+str
        sendmessage(str)
      end
    end
  end
  #--------------------------------------------------------------
  def services
    `cat /etc/services`.split("\n").inject({}) do |result, serv|
      unless /^#/.match(serv) or serv.eql?("")
        serv_data = serv.split(/\t+/)
        pp = serv_data[1].split("/")
        result[pp[0]] = {:service => serv_data[0], :port => pp[0], :protocol => pp[1]}
      end
      result
    end
  end
  #--------------------------------------------------------------
  def socket_processes
    `lsof  -i -n`.split("\n")[1..-1].inject({}) do |result, s|
      unless /^lsof/.match(s)
        s_data = s.strip.split(/\s+/)
        m = /(.*)->.*/.match(s_data[7]) || /.*:(.*)/.match(s_data[7])
        local_port = m.captures.first.split(":").last
        result[local_port] = s_data[0]
      end
      result
    end
  end
  #--------------------------------------------------------------
  def listening_tcp_sockets
    # TODO
  end
  #--------------------------------------------------------------
  def connected_tcp_sockets
    # TODO
  end
  #--------------------------------------------------------------
end

EM.run {
  puts "-> Launching EventMachine Run Event"
  chatbot = GtalkBot.new()
  chatbot.sendmessage("GTalkBot Initialized!")
}
