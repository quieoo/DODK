
from ast import While
import logging
import time
import grpc
import grpc_orchestrator_pb2
import grpc_orchestrator_pb2_grpc
import sys, getopt
from ftplib import FTP


def print_help():
    print("-a, --address <IP address>")
    print("     gRPC server address")
    print("-p, --port <port>")
    print("     gRPC server port listen on")
    

def cmd_usage():
    print("create <program_name> --cmd_args <argments>")
    print("     create remote program with args followed in string, return pid of remote program if succesfully")
    print("     example: create app_simple_fwd_vnf -l 0-1 -n 4 -F -ll 3")
    print("destroy <pid>")
    print("     destroy remote program with specified pid")
    print("list")
    print("     list remote programs")
    print("push <file_path>")
    print("     push local app to remote device")

def create(stub, cmd):
    create_response=stub.Create(grpc_orchestrator_pb2.CMD(cmd_str=cmd))
    if create_response.err_status.is_error:
        print(f'Error:{create_response.err_status.error_msg}')
    else:
        print(f'gRPC Create with uid: {create_response.uid.uid}')

def create_attach(stub, cmd):
    reply=stub.Create_Attach(grpc_orchestrator_pb2.CMD(cmd_str=cmd))
    for rp in reply:
        print(rp.str)

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

def push_file(path,ip_addr):
    ftp = FTP(host=ip_addr, user='host', passwd='123456')
    ftp.storbinary('STOR '+path, open(path, 'rb'))


def main(argv):
    address='localhost'
    port='50051'
    operation=-1
    program=''
    pid=''
    try:
        opts, args = getopt.getopt(argv,"ha:p",["help", "address=", "port"])
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

    
    channel=grpc.insecure_channel(address+':'+port)
    stub=grpc_orchestrator_pb2_grpc.OrchestratorStub(channel)
    print(">> Connectted with Orchestor server ("+address+":"+port+")")
    while 1:
        cmd=input(">> ")
        if cmd == "quit":
            break
        if cmd == "help":
            cmd_usage()
        if cmd=="list":
            get_list(stub)
        cmds=cmd.split(" ",1)
        if cmds[0]=="create":
            create(stub, cmds[1])
        if cmds[0]=="create_attach":
            create_attach(stub, cmds[1])
        if cmds[0]=="destroy":
            destroy(stub, cmds[1])
        if cmds[0]=="push":
            push_file(cmds[1], address)
if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except BaseException as e:
        if isinstance(e, KeyboardInterrupt):
            print("Quit")