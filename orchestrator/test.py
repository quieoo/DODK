import sys, getopt


def print_help():
    print("-a, --address <IP address>")
    print("     gRPC server address")
    print("-p, --port <port>")
    print("     gRPC server port listen on")
    print("-c, --create <program_name>")
    print("     create remote program with args followed in string, return pid of remote program if succesfully")
    print("     example: python3 grpc_client.py --create app_simple_fwd_vnf --cmd_args '-l 0-3 -n 4 -ll 3'")
    print("-s, --cmd_args <argements>")
    print("     argements for creating remote programs")
    print("-d, --destroy <pid>")
    print("     destroy remote program with specified pid")
    print("-l, --list")
    print("     list remote programs")

def create(program, args):
    print(f'create programe {program} with args: {args}')
def destroy(pid):
    print(f'destroy program {pid}')
def get_list():
    print('get program list')

def main(argv):
    address=''
    port=0
    operation=-1
    program=''
    pid=-1
    try:
        opts, args = getopt.getopt(argv,"ha:pc:d:ls:",["help", "address=", "port", "create=", "destroy=", "list", "cmd_args="])
    except getopt.GetoptError:
        print_help()
        sys.exit(2)
    for opt,arg in opts:
        if opt in ("-h", "--help"):
            print_help()
            sys.exit()
        elif opt in ("-a", "--address"):
            address=arg
        elif opt in ("-p", "--port"):
            port=int(arg)
        elif opt in ("-c", "--create"):
            operation=0
            program=arg
        elif opt in ("-d", "--destroy"):
            operation=1
            pid=int(arg)
        elif opt in ("-l", "--list"):
            operation=2
        elif opt in ("-s", "--cmd_args"):
            cmd_args=arg

    if operation == 0:
        create(program, cmd_args)
    elif operation == 1:
        destroy(pid)
    elif operation == 2:
        get_list()
    
        

if __name__ == "__main__":
   main(sys.argv[1:])