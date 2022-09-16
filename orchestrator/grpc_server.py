from ast import IsNot
from concurrent import futures
from distutils.util import execute
from genericpath import isdir, isfile
import logging
from operator import is_not
from pickle import NONE
from posixpath import join
import signal
import subprocess
import time
from unittest import result
import grpc
import grpc_orchestrator_pb2
import grpc_orchestrator_pb2_grpc
import os

path='../build/app/'
LIFETIME_CHECK_NUM_RETRIES          = 3
LIFETIME_CHECK_SLEEP_PERIOD_SECONDS = 10

class OrchestratorServicer(grpc_orchestrator_pb2_grpc.OrchestratorServicer):
    def GetProgramList(self, request, context):
        result=[]
        dirlist=os.listdir(path)
        for i in dirlist:
            Completepath = join(path,i)
            if isfile(Completepath):
                out_bytes = subprocess.check_output(["./"+Completepath, "-h"])
                out_text = out_bytes.decode('utf-8')
                result.append('APP: '+i+out_text)                
        return grpc_orchestrator_pb2.ProgramList(program_names=result)

    def Create(self, request, context):
        print(f'Creating: {execute_path} {request.cmdline}')
        execute_path=join(path, request.program_name)
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


        

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    grpc_orchestrator_pb2_grpc.add_OrchestratorServicer_to_server(OrchestratorServicer(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print("gRPC orchetrator waiting for request...")
    server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig()
    serve()