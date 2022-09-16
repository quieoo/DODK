
import logging
import time
import grpc
import grpc_orchestrator_pb2
import grpc_orchestrator_pb2_grpc
import sys, getopt


def print_help():
    print("-a, --address <IP address>")
    print("     gRPC server address")
    print("-p, --port <port>")
    print("     gRPC server port listen on")
    print("-c, --create <program_name>")
    print("     create remote program with args followed in string, return pid of remote program if succesfully")
    print("     example: python3 grpc_client.py --create app_simple_fwd_vnf --cmd_args '-l 0-3 -n 4 -ll 3' --address 101.76.213.102 --port 50051")
    print("-s, --cmd_args <argements>")
    print("     argements for creating remote programs")
    print("-d, --destroy <pid>")
    print("     destroy remote program with specified pid")
    print("-l, --list")
    print("     list remote programs")

def create(stub, program, args):
    arglist=grpc_orchestrator_pb2.Args(program_name=program, cmdline=args)
    create_response=stub.Create(arglist)
    if create_response.err_status.is_error:
        print(f'Error:{create_response.err_status.error_msg}')
    else:
        print(f'gRPC Create: {create_response.uid.uid}')

def destroy(stub, pid):
    print('Trying to terminate......')
    uid=grpc_orchestrator_pb2.Uid(uid=pid)
    terminate_response=stub.Destroy(uid)
    if terminate_response.is_error:
        print(f'Error:{terminate_response.error_msg}')
    else:
        print('gRPC Terminated')


def get_list(stub):
    plr=grpc_orchestrator_pb2.ProgramListReq()
    pl=stub.GetProgramList(plr)
    for p in pl.program_names:
        print(p)

def main(argv):
    address='localhost'
    port='50051'
    operation=-1
    program=''
    pid=''
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
            port=arg
        elif opt in ("-c", "--create"):
            operation=0
            program=arg
        elif opt in ("-d", "--destroy"):
            operation=1
            pid=arg
        elif opt in ("-l", "--list"):
            operation=2
        elif opt in ("-s", "--cmd_args"):
            cmd_args=arg

    if operation == -1:
        sys.exit()
    
    channel=grpc.insecure_channel(address+':'+port)
    stub=grpc_orchestrator_pb2_grpc.OrchestratorStub(channel)
    if operation == 0:
        create(stub, program, cmd_args)
    elif operation == 1:
        destroy(stub, pid)
    elif operation == 2:
        get_list(stub)
    
        

if __name__ == "__main__":
   main(sys.argv[1:])