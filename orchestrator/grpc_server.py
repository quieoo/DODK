from ast import IsNot
from concurrent import futures
from genericpath import  isfile
import logging
from operator import is_not
from pickle import NONE
from posixpath import join
import signal
import subprocess
import grpc
from grpc import server
import grpc_orchestrator_pb2
import grpc_orchestrator_pb2_grpc
import os
import threading

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


path='../build/app/'
LIFETIME_CHECK_NUM_RETRIES          = 3
LIFETIME_CHECK_SLEEP_PERIOD_SECONDS = 10

class OrchestratorServicer(grpc_orchestrator_pb2_grpc.OrchestratorServicer):
    def GetProgramList(self, request, context):
        result=[]
        files="-------file list----------\n"
        dirlist=os.listdir(path)
        for i in dirlist:
            Completepath = join(path,i)
            if isfile(Completepath):
                files+=Completepath+"\n"
                try:
                    out_bytes = subprocess.check_output(["./"+Completepath, "-h"])
                    out_text = out_bytes.decode('utf-8')
                except BaseException:
                    print("Catch execure file error: "+Completepath)
                    continue
                result.append('APP: '+i+out_text)
        result.append(files)
        return grpc_orchestrator_pb2.ProgramList(program_names=result)

    def Create(self, request, context):
        execute_path=join(path, request.program_name)
        print(f'Creating: {execute_path} {request.cmdline}')
        
        rich_status = grpc_orchestrator_pb2.RichStatus(err_status=grpc_orchestrator_pb2.Status(is_error=True))

        if isfile(execute_path) is not True:
            rich_status.err_status.error_msg=f'Unknown program name: {request.program_name}'
            return rich_status
        
        pid=os.fork()
        if pid==0:
            request_args = request.cmdline.split(' ')
            cmd_args  = [execute_path]
            cmd_args += request_args
            os.execv(execute_path, cmd_args)
        rich_status.err_status.is_error = False
        rich_status.uid.uid=str(pid)
        print('Create successfully')
        return rich_status
    
    def Destroy(self, request, context):
        print(f'Destory process {request.uid}')
        program_pid=int(request.uid)
        os.kill(program_pid, signal.SIGTERM)
        return grpc_orchestrator_pb2.Status(is_error=False, error_msg=NONE)



def start_ftp_server():
    authorizer = DummyAuthorizer()
    authorizer.add_user('host', '123456', path, perm="elradfmw")
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.passive_ports = range(2000,20033)
    ftp_server = FTPServer(('0.0.0.0', 21), handler)
    ftp_server.serve_forever()




if __name__ == '__main__':
    try:
        logging.basicConfig()
        thread_ftp=threading.Thread(target=start_ftp_server,daemon=1)
        thread_ftp.start()

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        grpc_orchestrator_pb2_grpc.add_OrchestratorServicer_to_server(OrchestratorServicer(), server)
        server.add_insecure_port('[::]:50051')
        server.start()
        print("gRPC orchetrator is Ready")
        server.wait_for_termination()
    except BaseException as e:
        if isinstance(e, KeyboardInterrupt):
            server.stop(grace=0)
            print("Quit")
            