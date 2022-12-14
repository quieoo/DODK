# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: grpc_orchestrator.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x17grpc_orchestrator.proto\x12\x0borchestaror\"\x10\n\x0eProgramListReq\"$\n\x0bProgramList\x12\x15\n\rprogram_names\x18\x01 \x03(\t\"\x16\n\x03\x43MD\x12\x0f\n\x07\x63md_str\x18\x01 \x01(\t\"\x12\n\x03Uid\x12\x0b\n\x03uid\x18\x01 \x01(\t\"-\n\x06Status\x12\x10\n\x08is_error\x18\x01 \x01(\x08\x12\x11\n\terror_msg\x18\x02 \x01(\t\"T\n\nRichStatus\x12\x1d\n\x03uid\x18\x01 \x01(\x0b\x32\x10.orchestaror.Uid\x12\'\n\nerr_status\x18\x02 \x01(\x0b\x32\x13.orchestaror.Status\"\x14\n\x05Reply\x12\x0b\n\x03str\x18\x01 \x01(\t2\xf7\x01\n\x0cOrchestrator\x12G\n\x0eGetProgramList\x12\x1b.orchestaror.ProgramListReq\x1a\x18.orchestaror.ProgramList\x12\x33\n\x06\x43reate\x12\x10.orchestaror.CMD\x1a\x17.orchestaror.RichStatus\x12\x30\n\x07\x44\x65stroy\x12\x10.orchestaror.Uid\x1a\x13.orchestaror.Status\x12\x37\n\rCreate_Attach\x12\x10.orchestaror.CMD\x1a\x12.orchestaror.Reply0\x01\x62\x06proto3')



_PROGRAMLISTREQ = DESCRIPTOR.message_types_by_name['ProgramListReq']
_PROGRAMLIST = DESCRIPTOR.message_types_by_name['ProgramList']
_CMD = DESCRIPTOR.message_types_by_name['CMD']
_UID = DESCRIPTOR.message_types_by_name['Uid']
_STATUS = DESCRIPTOR.message_types_by_name['Status']
_RICHSTATUS = DESCRIPTOR.message_types_by_name['RichStatus']
_REPLY = DESCRIPTOR.message_types_by_name['Reply']
ProgramListReq = _reflection.GeneratedProtocolMessageType('ProgramListReq', (_message.Message,), {
  'DESCRIPTOR' : _PROGRAMLISTREQ,
  '__module__' : 'grpc_orchestrator_pb2'
  # @@protoc_insertion_point(class_scope:orchestaror.ProgramListReq)
  })
_sym_db.RegisterMessage(ProgramListReq)

ProgramList = _reflection.GeneratedProtocolMessageType('ProgramList', (_message.Message,), {
  'DESCRIPTOR' : _PROGRAMLIST,
  '__module__' : 'grpc_orchestrator_pb2'
  # @@protoc_insertion_point(class_scope:orchestaror.ProgramList)
  })
_sym_db.RegisterMessage(ProgramList)

CMD = _reflection.GeneratedProtocolMessageType('CMD', (_message.Message,), {
  'DESCRIPTOR' : _CMD,
  '__module__' : 'grpc_orchestrator_pb2'
  # @@protoc_insertion_point(class_scope:orchestaror.CMD)
  })
_sym_db.RegisterMessage(CMD)

Uid = _reflection.GeneratedProtocolMessageType('Uid', (_message.Message,), {
  'DESCRIPTOR' : _UID,
  '__module__' : 'grpc_orchestrator_pb2'
  # @@protoc_insertion_point(class_scope:orchestaror.Uid)
  })
_sym_db.RegisterMessage(Uid)

Status = _reflection.GeneratedProtocolMessageType('Status', (_message.Message,), {
  'DESCRIPTOR' : _STATUS,
  '__module__' : 'grpc_orchestrator_pb2'
  # @@protoc_insertion_point(class_scope:orchestaror.Status)
  })
_sym_db.RegisterMessage(Status)

RichStatus = _reflection.GeneratedProtocolMessageType('RichStatus', (_message.Message,), {
  'DESCRIPTOR' : _RICHSTATUS,
  '__module__' : 'grpc_orchestrator_pb2'
  # @@protoc_insertion_point(class_scope:orchestaror.RichStatus)
  })
_sym_db.RegisterMessage(RichStatus)

Reply = _reflection.GeneratedProtocolMessageType('Reply', (_message.Message,), {
  'DESCRIPTOR' : _REPLY,
  '__module__' : 'grpc_orchestrator_pb2'
  # @@protoc_insertion_point(class_scope:orchestaror.Reply)
  })
_sym_db.RegisterMessage(Reply)

_ORCHESTRATOR = DESCRIPTOR.services_by_name['Orchestrator']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _PROGRAMLISTREQ._serialized_start=40
  _PROGRAMLISTREQ._serialized_end=56
  _PROGRAMLIST._serialized_start=58
  _PROGRAMLIST._serialized_end=94
  _CMD._serialized_start=96
  _CMD._serialized_end=118
  _UID._serialized_start=120
  _UID._serialized_end=138
  _STATUS._serialized_start=140
  _STATUS._serialized_end=185
  _RICHSTATUS._serialized_start=187
  _RICHSTATUS._serialized_end=271
  _REPLY._serialized_start=273
  _REPLY._serialized_end=293
  _ORCHESTRATOR._serialized_start=296
  _ORCHESTRATOR._serialized_end=543
# @@protoc_insertion_point(module_scope)
