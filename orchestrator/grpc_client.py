
import logging
import time
import grpc
import grpc_orchestrator_pb2
import grpc_orchestrator_pb2_grpc

def run():
    with grpc.insecure_channel('101.76.218.115:50051') as channel:
        stub=grpc_orchestrator_pb2_grpc.OrchestratorStub(channel)
        plr=grpc_orchestrator_pb2.ProgramListReq()
        pl=stub.GetProgramList(plr)
        for p in pl.program_names:
            print(p)

        # create dodk flow app
        arglist=grpc_orchestrator_pb2.Args(program_name='app_simple_fwd_vnf', cmdline='-l 0-3 -n 4',port=444)
        #arglist=grpc_orchestrator_pb2.Args(program_name='/home/quieoo/Desktop/hello', cmdline='-h',port=444)
        create_response=stub.Create(arglist)
        if create_response.err_status.is_error:
            print(f'Error:{create_response.err_status.error_msg}')
        else:
            print(f'gRPC Create: {create_response.uid.uid}')

        # sleep and terminate
        time.sleep(3)
        uid=grpc_orchestrator_pb2.Uid(uid=create_response.uid.uid)
        terminate_response=stub.Destroy(uid)
        if terminate_response.is_error:
            print(f'Error:{terminate_response.error_msg}')
        else:
            print('gRPC Terminated')


if __name__ == '__main__':
    logging.basicConfig()
    run()