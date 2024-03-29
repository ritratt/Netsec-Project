# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ct/proto/test_message.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)


import ct.proto.tls_options_pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='ct/proto/test_message.proto',
  package='ct',
  serialized_pb='\n\x1b\x63t/proto/test_message.proto\x12\x02\x63t\x1a\x1a\x63t/proto/tls_options.proto\"\xa2\x05\n\x0bTestMessage\x12\x1b\n\x0bskip_uint32\x18\x01 \x01(\rB\x06\x82\xb5\x18\x02P\x01\x12\x16\n\x06uint_8\x18\x02 \x01(\rB\x06\x82\xb5\x18\x02\x08\x01\x12\x17\n\x07uint_16\x18\x03 \x01(\rB\x06\x82\xb5\x18\x02\x08\x02\x12\x17\n\x07uint_24\x18\x04 \x01(\rB\x06\x82\xb5\x18\x02\x08\x03\x12\x0f\n\x07uint_32\x18\x05 \x01(\r\x12\x17\n\x07uint_48\x18\x06 \x01(\x04\x42\x06\x82\xb5\x18\x02\x08\x06\x12\x0f\n\x07uint_64\x18\x07 \x01(\x04\x12\x1a\n\nskip_bytes\x18\x08 \x01(\x0c\x42\x06\x82\xb5\x18\x02P\x01\x12\x1b\n\x0b\x66ixed_bytes\x18\t \x01(\x0c\x42\x06\x82\xb5\x18\x02\x18\x02\x12\x19\n\tvar_bytes\x18\n \x01(\x0c\x42\x06\x82\xb5\x18\x02(\x10\x12!\n\nvar_bytes2\x18\x0b \x01(\x0c\x42\r\x82\xb5\x18\x02 \x04\x82\xb5\x18\x03(\x80\x02\x12\"\n\x0cvector_bytes\x18\x0c \x03(\x0c\x42\x0c\x82\xb5\x18\x02(\n\x82\xb5\x18\x02\x38\x14\x12#\n\rvector_uint32\x18\r \x03(\rB\x0c\x82\xb5\x18\x02\x30\x04\x82\xb5\x18\x02\x38\x08\x12+\n\ttest_enum\x18\x0e \x01(\x0e\x32\x18.ct.TestMessage.TestEnum\x12,\n\rselect_uint32\x18\x0f \x01(\rB\x15\x82\xb5\x18\x0b\x42\ttest_enum\x82\xb5\x18\x02H\x01\x12\x39\n\x10\x65mbedded_message\x18\x10 \x01(\x0b\x32\x1f.ct.TestMessage.EmbeddedMessage\x12\x41\n\x10repeated_message\x18\x11 \x03(\x0b\x32\x1f.ct.TestMessage.EmbeddedMessageB\x06\x82\xb5\x18\x02\x38\x08\x1a*\n\x0f\x45mbeddedMessage\x12\x17\n\x07uint_32\x18\x01 \x01(\rB\x06\x82\xb5\x18\x02\x08\x02\",\n\x08TestEnum\x12\n\n\x06\x45NUM_0\x10\x00\x12\n\n\x06\x45NUM_1\x10\x01\x1a\x08\x8a\xb5\x18\x04\x10\xff\xff\x03')



_TESTMESSAGE_TESTENUM = _descriptor.EnumDescriptor(
  name='TestEnum',
  full_name='ct.TestMessage.TestEnum',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='ENUM_0', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ENUM_1', index=1, number=1,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=_descriptor._ParseOptions(descriptor_pb2.EnumOptions(), '\212\265\030\004\020\377\377\003'),
  serialized_start=694,
  serialized_end=738,
)


_TESTMESSAGE_EMBEDDEDMESSAGE = _descriptor.Descriptor(
  name='EmbeddedMessage',
  full_name='ct.TestMessage.EmbeddedMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='uint_32', full_name='ct.TestMessage.EmbeddedMessage.uint_32', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\010\002')),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=650,
  serialized_end=692,
)

_TESTMESSAGE = _descriptor.Descriptor(
  name='TestMessage',
  full_name='ct.TestMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='skip_uint32', full_name='ct.TestMessage.skip_uint32', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002P\001')),
    _descriptor.FieldDescriptor(
      name='uint_8', full_name='ct.TestMessage.uint_8', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\010\001')),
    _descriptor.FieldDescriptor(
      name='uint_16', full_name='ct.TestMessage.uint_16', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\010\002')),
    _descriptor.FieldDescriptor(
      name='uint_24', full_name='ct.TestMessage.uint_24', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\010\003')),
    _descriptor.FieldDescriptor(
      name='uint_32', full_name='ct.TestMessage.uint_32', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint_48', full_name='ct.TestMessage.uint_48', index=5,
      number=6, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\010\006')),
    _descriptor.FieldDescriptor(
      name='uint_64', full_name='ct.TestMessage.uint_64', index=6,
      number=7, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='skip_bytes', full_name='ct.TestMessage.skip_bytes', index=7,
      number=8, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value="",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002P\001')),
    _descriptor.FieldDescriptor(
      name='fixed_bytes', full_name='ct.TestMessage.fixed_bytes', index=8,
      number=9, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value="",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\030\002')),
    _descriptor.FieldDescriptor(
      name='var_bytes', full_name='ct.TestMessage.var_bytes', index=9,
      number=10, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value="",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002(\020')),
    _descriptor.FieldDescriptor(
      name='var_bytes2', full_name='ct.TestMessage.var_bytes2', index=10,
      number=11, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value="",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002 \004\202\265\030\003(\200\002')),
    _descriptor.FieldDescriptor(
      name='vector_bytes', full_name='ct.TestMessage.vector_bytes', index=11,
      number=12, type=12, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002(\n\202\265\030\0028\024')),
    _descriptor.FieldDescriptor(
      name='vector_uint32', full_name='ct.TestMessage.vector_uint32', index=12,
      number=13, type=13, cpp_type=3, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\0020\004\202\265\030\0028\010')),
    _descriptor.FieldDescriptor(
      name='test_enum', full_name='ct.TestMessage.test_enum', index=13,
      number=14, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='select_uint32', full_name='ct.TestMessage.select_uint32', index=14,
      number=15, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\013B\ttest_enum\202\265\030\002H\001')),
    _descriptor.FieldDescriptor(
      name='embedded_message', full_name='ct.TestMessage.embedded_message', index=15,
      number=16, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='repeated_message', full_name='ct.TestMessage.repeated_message', index=16,
      number=17, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\0028\010')),
  ],
  extensions=[
  ],
  nested_types=[_TESTMESSAGE_EMBEDDEDMESSAGE, ],
  enum_types=[
    _TESTMESSAGE_TESTENUM,
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=64,
  serialized_end=738,
)

_TESTMESSAGE_EMBEDDEDMESSAGE.containing_type = _TESTMESSAGE;
_TESTMESSAGE.fields_by_name['test_enum'].enum_type = _TESTMESSAGE_TESTENUM
_TESTMESSAGE.fields_by_name['embedded_message'].message_type = _TESTMESSAGE_EMBEDDEDMESSAGE
_TESTMESSAGE.fields_by_name['repeated_message'].message_type = _TESTMESSAGE_EMBEDDEDMESSAGE
_TESTMESSAGE_TESTENUM.containing_type = _TESTMESSAGE;
DESCRIPTOR.message_types_by_name['TestMessage'] = _TESTMESSAGE

class TestMessage(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType

  class EmbeddedMessage(_message.Message):
    __metaclass__ = _reflection.GeneratedProtocolMessageType
    DESCRIPTOR = _TESTMESSAGE_EMBEDDEDMESSAGE

    # @@protoc_insertion_point(class_scope:ct.TestMessage.EmbeddedMessage)
  DESCRIPTOR = _TESTMESSAGE

  # @@protoc_insertion_point(class_scope:ct.TestMessage)


_TESTMESSAGE_EMBEDDEDMESSAGE.fields_by_name['uint_32'].has_options = True
_TESTMESSAGE_EMBEDDEDMESSAGE.fields_by_name['uint_32']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\010\002')
_TESTMESSAGE_TESTENUM.has_options = True
_TESTMESSAGE_TESTENUM._options = _descriptor._ParseOptions(descriptor_pb2.EnumOptions(), '\212\265\030\004\020\377\377\003')
_TESTMESSAGE.fields_by_name['skip_uint32'].has_options = True
_TESTMESSAGE.fields_by_name['skip_uint32']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002P\001')
_TESTMESSAGE.fields_by_name['uint_8'].has_options = True
_TESTMESSAGE.fields_by_name['uint_8']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\010\001')
_TESTMESSAGE.fields_by_name['uint_16'].has_options = True
_TESTMESSAGE.fields_by_name['uint_16']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\010\002')
_TESTMESSAGE.fields_by_name['uint_24'].has_options = True
_TESTMESSAGE.fields_by_name['uint_24']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\010\003')
_TESTMESSAGE.fields_by_name['uint_48'].has_options = True
_TESTMESSAGE.fields_by_name['uint_48']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\010\006')
_TESTMESSAGE.fields_by_name['skip_bytes'].has_options = True
_TESTMESSAGE.fields_by_name['skip_bytes']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002P\001')
_TESTMESSAGE.fields_by_name['fixed_bytes'].has_options = True
_TESTMESSAGE.fields_by_name['fixed_bytes']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002\030\002')
_TESTMESSAGE.fields_by_name['var_bytes'].has_options = True
_TESTMESSAGE.fields_by_name['var_bytes']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002(\020')
_TESTMESSAGE.fields_by_name['var_bytes2'].has_options = True
_TESTMESSAGE.fields_by_name['var_bytes2']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002 \004\202\265\030\003(\200\002')
_TESTMESSAGE.fields_by_name['vector_bytes'].has_options = True
_TESTMESSAGE.fields_by_name['vector_bytes']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\002(\n\202\265\030\0028\024')
_TESTMESSAGE.fields_by_name['vector_uint32'].has_options = True
_TESTMESSAGE.fields_by_name['vector_uint32']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\0020\004\202\265\030\0028\010')
_TESTMESSAGE.fields_by_name['select_uint32'].has_options = True
_TESTMESSAGE.fields_by_name['select_uint32']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\013B\ttest_enum\202\265\030\002H\001')
_TESTMESSAGE.fields_by_name['repeated_message'].has_options = True
_TESTMESSAGE.fields_by_name['repeated_message']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), '\202\265\030\0028\010')
# @@protoc_insertion_point(module_scope)
