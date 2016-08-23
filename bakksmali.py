#! /usr/bin/python
# -*- coding: utf8 -*-
# author: yanfeng.wyf
# author: zke1e

import sys
import struct
import array
import os

from leb128 import *
from dex_ints import *

DEX_MAGIC = "dex\n"
DEX_OPT_MAGIC = "dey\n"


class method_code:
    def __init__(self, dex_object, offset):
        format = "H"
        self.registers_size, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        self.ins_size, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        self.outs_size, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        self.tries_size, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        format = "I"
        self.debug_info_off, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        self.insns_size, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        self.insns = offset
        offset += 2 * self.insns_size
        if self.insns_size % 2 == 1:
            offset += 2
        if self.tries_size == 0:
            self.tries = 0
            self.handlers = 0
        else:
            self.tries = offset
            self.handlers = offset + self.tries_size * struct.calcsize("I2H")

    def get_param_list(self, dex_object):
        if self.debug_info_off != 0:
            return parse_debug_info_method_parameter_list(dex_object, self.debug_info_off)
        return []

    def printf(self, fd, dex_object, prefix=""):
        fd.write("\t\t%s %s"%(".registers",self.registers_size)+'\n')
        fd.write("\t\t%s %s"%(".params",self.get_param_list(dex_object))+'\n')
        parse_instruction(fd, dex_object.m_content[self.insns:self.insns + self.insns_size * 2], self.insns, dex_object)


class dex_class:
    def __init__(self, dex_object, classid):
        if classid >= dex_object.m_classDefSize:
            return ""
        offset = dex_object.m_classDefOffset + classid * struct.calcsize("8I")
        self.offset = offset
        format = "I"
        # 获取class_def的类型
        self.thisClass, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        # 访问标志
        self.modifiers, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        # 父类
        self.superClass, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        # 接口偏移地址
        self.interfacesOff, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        # 源文件名
        self.sourceFileIdx, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        # 注解
        self.annotationsOff, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        # classData偏移
        self.classDataOff, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        # 静态数据偏移
        self.staticValuesOff, = struct.unpack_from(format, dex_object.m_content, offset)
        offset += struct.calcsize(format)
        self.index = classid
        self.interfacesSize = 0
        if self.interfacesOff != 0:
            # 得到接口size
            self.interfacesSize, = struct.unpack_from("I", dex_object.m_content, self.interfacesOff)
        if self.classDataOff != 0:
            offset = self.classDataOff
            # 静态字段个数
            count, self.numStaticFields = get_uleb128(dex_object.m_content[offset:])
            offset += count
            # 实例字段个数
            count, self.numInstanceFields = get_uleb128(dex_object.m_content[offset:])
            offset += count
            # 直接方法个数
            count, self.numDirectMethods = get_uleb128(dex_object.m_content[offset:])
            offset += count
            # 虚方法个数
            count, self.numVirtualMethods = get_uleb128(dex_object.m_content[offset:])
        else:
            self.numStaticFields = 0
            self.numInstanceFields = 0
            self.numDirectMethods = 0
            self.numVirtualMethods = 0

    def printf(self, dex_object):

        # if dex_object.gettypename(self.thisClass)!="Landroid/Manifest$permission;":
        #	return
        # print "%-20s:%08x:%10d  %s"%("thisClass",self.thisClass,self.thisClass,dex_object.gettypename(self.thisClass))

        dir = os.path.dirname(dex_object.gettypename(self.thisClass)[1:])
        if dir.startswith("android"):
            return
        dir = "Out/" + dir
        file = os.path.basename(dex_object.gettypename(self.thisClass))
        if os.path.exists(dir) == 0:
            os.makedirs(dir)

        smali = open(dir + '/' + file[:-1] + '.smali', "w")

        smali.write("%s %s" % (".this", dex_object.gettypename(self.thisClass)) + '\n')
        # print "%-20s:%08x:%10d  %s"%("superClass",self.superClass,self.superClass,dex_object.gettypename(self.superClass))
        smali.write("%s %s" % (".super", dex_object.gettypename(self.superClass)) + '\n')

        # 指向DexTypeList的DexTypeItem数组
        offset = self.interfacesOff + struct.calcsize("I")
        for n in xrange(0, self.interfacesSize):
            # 得到typeid
            typeid, = struct.unpack_from("H", dex_object.m_content, offset)
            offset += struct.calcsize("H")
            # print "\t\t"+ dex_object.gettypename(typeid)
            smali.write(".implements\t" + dex_object.gettypename(typeid) + '\n')

        smali.write("%s %s" % (".source", dex_object.getstringbyid(self.sourceFileIdx))+'\n\n')
        offset = self.classDataOff
        # 主要是为了跳过DexClassHeader的大小
        n, tmp = get_uleb128(dex_object.m_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_content[offset:offset + 5])
        offset += n
        n, tmp = get_uleb128(dex_object.m_content[offset:offset + 5])
        offset += n
        field_idx = 0
        for i in xrange(0, self.numStaticFields):
            n, field_idx_diff = get_uleb128(dex_object.m_content[offset:offset + 5])
            offset += n
            field_idx += field_idx_diff
            # print dex_object.getfieldfullname(field_idx),
            n, modifiers = get_uleb128(dex_object.m_content[offset:offset + 5])
            smali.write(".filed " + dex_object.get_access_flags(modifiers)+' '+dex_object.getfieldfullname(field_idx) + '\n')
            offset += n
            if self.staticValuesOff:
                staticoffset = get_static_offset(dex_object.m_content[self.staticValuesOff:], i)
                if staticoffset == -1:
                    print "0;"
                    continue

        field_idx = 0
        for i in xrange(0, self.numInstanceFields):
            n, field_idx_diff = get_uleb128(dex_object.m_content[offset:offset + 5])
            offset += n
            field_idx += field_idx_diff
            n, modifiers = get_uleb128(dex_object.m_content[offset:offset + 5])
            smali.write(".filed " +dex_object.get_access_flags(modifiers)+' '+dex_object.getfieldfullname(field_idx) + '\n')
            offset += n

        method_idx = 0
        for i in xrange(0, self.numDirectMethods):
            n, method_idx_diff = get_uleb128(dex_object.m_content[offset:offset + 5])
            offset += n
            n, access_flags = get_uleb128(dex_object.m_content[offset:offset + 5])
            offset += n
            n, code_off = get_uleb128(dex_object.m_content[offset:offset + 5])
            offset += n
            method_idx += method_idx_diff
            smali.write('\n'+dex_object.get_access_flags(access_flags)+' ')
            smali.write(dex_object.getmethodfullname(method_idx, True) + '\n')
            if code_off != 0:
                method_code(dex_object, code_off).printf(smali, dex_object, "\t\t")
        method_idx = 0
        for i in xrange(0, self.numVirtualMethods):
            n, method_idx_diff = get_uleb128(dex_object.m_content[offset:offset + 5])
            offset += n
            n, access_flags = get_uleb128(dex_object.m_content[offset:offset + 5])
            offset += n
            n, code_off = get_uleb128(dex_object.m_content[offset:offset + 5])
            offset += n
            method_idx += method_idx_diff
            smali.write('\n'+dex_object.get_access_flags(access_flags)+' ')
            smali.write( dex_object.getmethodfullname(method_idx, True) + '\n')
            if code_off != 0:
                method_code(dex_object, code_off).printf(smali, dex_object, "\t\t")
        smali.close()


def get_static_offset(content, index):
    offset = 0
    m, size = get_uleb128(content[offset:offset + 5])
    if index >= size:
        return -1
    offset += m
    for i in xrange(0, index):
        offset += get_encoded_value_size(content[offset:])
    return offset


def get_encoded_value_size(content):
    offset = 0
    arg_type, = struct.unpack_from("B", content, offset)
    offset += struct.calcsize("B")
    value_arg = arg_type >> 5
    value_type = arg_type & 0x1f
    if value_type in [0x2, 3, 4, 6, 0x10, 0x11, 0x17, 0x18, 0x19, 0x1a, 0x1b]:
        offset += (value_arg + 1)
    elif value_type == 0:
        offset += 1
    elif value_type == 0x1e or value_type == 0x1f:
        offset += 0
    elif value_type == 0x1d:
        offset += get_encoded_annotation_size(content[offset:])
    elif value_type == 0x1c:
        m, asize = get_uleb128(m_content[offset:offset + 5])
        offset += m
        for q in xrange(0, asize):
            offset += get_encoded_value_size(content[offset:])
    else:
        print "***************error parse encode_value**************"
    return offset


class field_annotation:
    def __init__(self, content):
        self.field_idx, self.annotations_off, = struct.unpack_from("2I", content)


class annotations_directory_item:
    def __init__(self, content, dex_object):
        self.class_annotations_off, self.fields_size, self.annotated_methods_size, self.annotated_parameters_size, = struct.unpack_from(
            "4I", content)
        self.m_fields_list = []
        self.m_methods_list = []
        self.m_parameters_list = []
        offset = struct.calcsize("4I")
        if self.fields_size:
            self.m_fields_list = array.array("L")
            self.m_fields_list.fromstring(content[offset:offset + 8 * self.fields_size])
        offset = offset + 4 * self.fields_size
        if self.annotated_methods_size:
            self.m_methods_list = array.array("L")
            self.m_methods_list.fromstring(content[offset:offset + 8 * self.annotated_methods_size])
        offset = offset + 4 * self.annotated_methods_size
        for i in xrange(0, annotated_methods_size):
            self.m_parameters_list = array.array("L")
            self.m_parameters_list.fromstring(content[offset:offset + 8 * self.annotated_parameters_size])
        content = dex_object.m_content
        for i in xrange(0, self.fields_size):
            size = self.m_fields_list[i * 2]
            offset = self.m_fields_list[i * 2 + 1]
            of = array.array("L")
            of.fromstring(content[offset:offset + 4 * size])
            for off in of:
                visibility = content[off]
                off += 1
                k, type_idx = get_uleb128(content[off:])
                off += k
                k, size = get_uleb128(content[off:])
                for m in xrange(0, size):
                    off += k
                    k, name_idx = get_uleb128(content[off:])
                    off += k
                    get_encoded_value(content[off:])


def parse_debug_info_method_parameter_list(dex_object, offset):
    parameter_list = []
    n, current_line = get_uleb128(dex_object.m_content[offset:offset + 5])
    offset += n
    n, parameters_size = get_uleb128(dex_object.m_content[offset:offset + 5])
    offset += n
    for i in xrange(0, parameters_size):
        n, string_idx = get_uleb128p1(dex_object.m_content[offset:offset + 5])
        if string_idx != -1:
            parameter_list.append(dex_object.getstringbyid(string_idx))
        offset += n
    return parameter_list


def parse_debug_info(lex_object, offset):
    print "===parse_debug_info====offset = %08x" % offset
    n, current_line = get_uleb128(lex_object.m_content[offset:offset + 5])
    offset += n
    n, parameters_size = get_uleb128(lex_object.m_content[offset:offset + 5])
    offset += n
    for i in xrange(0, parameters_size):
        n, string_idx = get_uleb128p1(lex_object.m_content[offset:offset + 5])
        if string_idx != -1:
            print lex_object.getstringbyid(string_idx)
        offset += n
    start = offset
    current_pc = 0
    print "===opcode====offset = %08x  line=%d pc=%d" % (offset, current_line, current_pc)

    totalsize = len(lex_object.m_content)
    while offset < totalsize:
        # bytecode = struct.unpack_from("B",lex_object.m_content,offset)
        bytecode = ord(lex_object.m_content[offset])
        offset += 1
        print "opcode[%02x]" % bytecode,
        if bytecode == 0:
            print ""
            break
        elif bytecode == 1:
            n, val = get_uleb128(lex_object.m_content[offset:offset + 5])
            current_pc += val;
            offset += n
            print "line=%d  pc=%x" % (current_line, current_pc)
        elif bytecode == 2:
            n, val = get_leb128(lex_object.m_content[offset:offset + 5])

            current_line += val
            offset += n
            print "line=%d  pc=%x   val=%08x(%d)" % (current_line, current_pc, val, val)
        elif bytecode == 3:
            n, register_num = get_uleb128(lex_object.m_content[offset:offset + 5])
            offset += n
            n, name_idx = get_uleb128p1(lex_object.m_content[offset:offset + 5])
            offset += n
            n, type_idx = get_uleb128p1(lex_object.m_content[offset:offset + 5])
            offset += n
            print "v%d %s %s  START_LOCAL" % (
            register_num, lex_object.gettypenamebyid(type_idx), lex_object.getstringbyid(name_idx))
        elif bytecode == 4:
            n, register_num = get_uleb128(lex_object.m_content[offset:offset + 5])
            offset += n
            n, name_idx = get_uleb128p1(lex_object.m_content[offset:offset + 5])
            offset += n
            n, type_idx = get_uleb128p1(lex_object.m_content[offset:offset + 5])
            offset += n
            n, sig_idx = get_uleb128p1(lex_object.m_content[offset:offset + 5])
            offset += n
            print "v%d %s %s   START_LOCAL_EXTENDED" % (
            register_num, lex_object.gettypenamebyid(type_idx), lex_object.getstringbyid(name_idx))
        elif bytecode == 5:
            n, register_num = get_uleb128(lex_object.m_content[offset:offset + 5])
            offset += n
            print "v%d  END_LOCAL" % register_num
        elif bytecode == 6:
            n, register_num = get_uleb128(lex_object.m_content[offset:offset + 5])
            offset += n
            print "v%d   register to restart" % register_num
        elif bytecode == 7:
            print "SET_PROLOGUE_END"
            pass
        elif bytecode == 8:
            print "SET_EPILOGUE_BEGIN"
            pass
        elif bytecode == 9:
            n, name_idx = get_uleb128(lex_object.m_content[offset:offset + 5])
            print "%s" % lex_object.getstringbyid(name_idx)
            offset += n
        else:
            adjusted_opcode = bytecode - 0xa
            current_line += (adjusted_opcode % 15) - 4
            current_pc += (adjusted_opcode / 15)
            # offset += 1
            print "line=%d  pc=%x  adjusted_opcode=%d  pc+ %d  line+%d" % (
            current_line, current_pc, adjusted_opcode, (adjusted_opcode / 15), (adjusted_opcode % 15) - 4)
    print "===parse_debug_info====offset = %08x$" % offset


def get_encoded_value(content):
    VALUE_SHORT = 0x2
    VALUE_CHAR = 0x3
    VALUE_INT = 0x4
    VALUE_LONG = 0x6
    VALUE_FLOAT = 0x10
    VALUE_DOUBLE = 0x11
    VALUE_STRING = 0x17
    VALUE_TYPE = 0x18
    VALUE_FIELD = 0x19
    VALUE_METHOD = 0x1a
    VALUE_ENUM = 0x1b
    VALUE_ARRAY = 0x1c
    VALUE_ANNOTATION = 0x1d
    VALUE_NULL = 0x1e
    VALUE_BOOLEAN = 0x1f
    type_enum = [0x0, 0x2, 0x3, 0x4, 0x6, 0x10, 0x11, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]
    size_type = ord(content[0])
    usebyte = 1

    size = size_type >> 5
    type = size_type & 0x1f
    if type not in size_type:
        print "encoded value error!"
    if type == 0 and size == 0:
        value, = struct.unpack_from("b", content, 1)
        usebyte += 1

    elif type == VALUE_SHORT:
        if size == 0:
            value, = struct.unpack_from("b", content, 1)
        elif size == 1:
            value, = struct.unpack_from("h", content, 1)
        else:
            print "encoded value error! type=short type=%d size=%d" % (type, size)
        usebyte += size + 1
    elif type == VALUE_CHAR:
        if size == 0:
            value, = struct.unpack_from("B", content, 1)
        elif size == 1:
            value, = struct.unpack_from("H", content, 1)
        else:
            print "encoded value error! type=char type=%d size=%d" % (type, size)
        usebyte += size + 1
    elif type == VALUE_INT:
        if size == 0:
            value, = struct.unpack_from("b", content, 1)
        elif size == 1:
            value, = struct.unpack_from("h", content, 1)
        elif size == 2:
            value = 0
        elif size == 3:
            value, = struct.unpack_from("i", content, 1)
        else:
            print "encoded value error! type=int type=%d size=%d" % (type, size)
        usebyte += size + 1

    elif type == VALUE_LONG:
        if size > 7:
            print "encoded value error! type=long type=%d size=%d" % (type, size)
        value = content[1:1 + size + 1]
        usebyte += size + 1
    elif type == VALUE_FLOAT:
        if size > 3:
            print "encoded value error! type=float type=%d size=%d" % (type, size)
        value = content[1:1 + size + 1]
        usebyte += size + 1
    elif type == VALUE_DOUBLE:
        if size > 7:
            print "encoded value error! type=double type=%d size=%d" % (type, size)
        value = content[1:1 + size + 1]
        usebyte += size + 1

    elif type == VALUE_STRING:
        if size > 3:
            print "encoded value error! type=double type=%d size=%d" % (type, size)
        value = content[1:1 + size + 1]
        usebyte += size + 1
    elif type == VALUE_TYPE:
        if size > 3:
            print "encoded value error! type=type type=%d size=%d" % (type, size)
        value = content[1:1 + size + 1]
        usebyte += size + 1

    elif type == VALUE_FIELD:
        if size > 3:
            print "encoded value error! type=field type=%d size=%d" % (type, size)
        value = content[1:1 + size + 1]
        usebyte += size + 1
    elif type == VALUE_METHOD:
        if size > 3:
            print "encoded value error! type=medhod type=%d size=%d" % (type, size)
        value = content[1:1 + size + 1]
        usebyte += size + 1
    elif type == VALUE_ENUM:
        if size > 3:
            print "encoded value error! type=enum type=%d size=%d" % (type, size)
        value = content[1:1 + size + 1]
        usebyte += size + 1
    elif type == VALUE_ARRAY:
        if size != 0:
            print "encoded value error! type=encoded_array type=%d size=%d" % (type, size)
        k, value = get_encoded_array(content[1:1 + size + 1])
        usebyte += k
    elif type == VALUE_ANNOTATION:
        if size != 0:
            print "encoded value error! type=encoded_annotation type=%d size=%d" % (type, size)
        k, type_idx = get_uleb128(content[1:])
        k1, s = get_uleb128(content[1 + k:])
        k1 = 1 + k + k1
        for n in xrange(0, s):
            k2, name_index = get_uleb128(content[k1:])
            k1 += k2
            k3, value = get_encoded_value(content[k1:])
            k1 += k3
        usebyte += k1
    elif type == VALUE_NULL:
        if size != 0:
            print "encoded value error! type=NULL  type=%d size=%d" % (type, size)
        value = "NULL"
    elif type == VALUE_BOOLEAN:
        value = size
    return usebyte, value


def get_encoded_array(content):
    offset, size = get_uleb128(content)
    userbyte = offset
    for i in xrange(0, size):
        off, value = get_encoded_value(content[offset:])
        offset += off
        userbyte += off
    return userbyte, value


def get_encoded_array_by_index(content, index):
    offset, size = get_uleb128(content)
    userbyte = offset
    for i in xrange(0, size):
        off, value = get_encoded_value(content[offset:])
        offset += off
        userbyte += off
        if index == i:
            return userbyte, value
    return offset


class annotations_directory_item:
    def __init__(self, content):
        self.m_class_annotations_off, self.m_fields_size, self.m_annotated_methods_size, self.m_annotated_parameters_size, = struct.unpack_from(
            "4I", content)
        pass


def shorty_decode(name):
    val = {"V": "void",
           "Z": "boolean",
           "B": "byte",
           "S": "short",
           "C": "char",
           "I": "int",
           "J": "long",
           "F": "float",
           "D": "double",
           "L": "L"
           }
    value = ""

    if name[-1] == ';':
        if name[0] == 'L':
            return name[1:-1].replace("/", ".")
        if name[0] == '[':
            if name[1] == 'L':
                return name[2:-1].replace("/", ".") + "[]"
            else:
                return name[1:-1].replace("/", ".") + "[]"
    i = 0
    for ch in name:
        if val.has_key(ch):
            if i != 0:
                value += " | "
            value += val[ch]
            i += 1
    if '[' in name:
        value += "[]"
    return value


def get_encoded_value_size(content):
    offset = 0
    arg_type, = struct.unpack_from("B", content, offset)
    offset += struct.calcsize("B")
    value_arg = arg_type >> 5
    value_type = arg_type & 0x1f
    if value_type in [0x2, 3, 4, 6, 0x10, 0x11, 0x17, 0x18, 0x19, 0x1a, 0x1b]:
        offset += (value_arg + 1)
    elif value_type == 0:
        offset += 1
    elif value_type == 0x1e or value_type == 0x1f:
        offset += 0
    elif value_type == 0x1d:
        offset += get_encoded_annotation_size(content[offset:])
    elif value_type == 0x1c:
        m, asize = get_uleb128(m_content[offset:5 + offset])
        offset += m
        for q in xrange(0, asize):
            offset += get_encoded_value_size(content[offset:])
    else:
        print "***************error parse encode_value**************"
    return offset


def get_encoded_annotation_size(content):
    offset = 0
    n, type_idx = get_uleb128(content[offset:5 + offset])
    offset += n
    n, size = get_uleb128(content[offset:5 + offset])
    offset += n
    for i in xrange(0, n):
        n, name_idx = get_uleb128(content[offset:5 + offset])
        offset += n
        offset += get_encoded_value_size(content[offset:])
    return offset


def parse_encoded_value(lex_object, content, is_root=False):
    offset = 0
    arg_type, = struct.unpack_from("B", content, offset)
    offset += struct.calcsize("B")
    value_arg = arg_type >> 5
    value_type = arg_type & 0x1f
    if value_type in [0x2, 3, 4, 6, 0x10, 0x11, 0x17, 0x18, 0x19, 0x1a, 0x1b]:
        sum = 0
        for q in xrange(0, value_arg + 1):
            mm = ord(content[offset + q])
            mm <<= 8 * q
            sum |= mm
        # sum += ord(content[offset+q])
        if value_type == 0x17:
            print "string@%d" % sum,
            print lex_object.getstringbyid(sum),
        elif value_type == 0x18:
            print "type@%d" % sum,
            print lex_object.gettypename(sum),
        elif value_type == 0x19:
            print "field@%d" % sum,
            print lex_object.getfieldname(sum),
        elif value_type == 0x1a:
            print "method@%d" % sum,
            print lex_object.getmethodname(sum),
        else:
            str = ""
            for q in xrange(0, value_arg + 1):
                str += "%02x " % (ord(content[offset + q]))
            print str,
        offset += (value_arg + 1)
    elif value_type == 0:
        print "%02x" % ord(content[offset]),
        offset += 1

    elif value_type == 0x1e:
        print "NULL",
    elif value_type == 0x1f:
        if value_arg == 0:
            print "False",
        else:
            print "True",
        offset += 0
    elif value_type == 0x1d:
        offset += parse_encoded_annotation(lex_object, content[offset:])
    elif value_type == 0x1c:
        m, asize = get_uleb128(content[offset:5])
        offset += m
        print "[%d]" % asize,
        for q in xrange(0, asize):
            offset += parse_encoded_value(lex_object, content[offset:], False)
    else:
        print "***************error parse encode_value**************"
    return offset


def parse_encoded_value1(lex_object, content, is_root=False):
    str1 = ""
    offset = 0
    arg_type, = struct.unpack_from("B", content, offset)
    offset += struct.calcsize("B")
    value_arg = arg_type >> 5
    value_type = arg_type & 0x1f
    if value_type in [0x2, 3, 4, 6, 0x10, 0x11, 0x17, 0x18, 0x19, 0x1a, 0x1b]:
        sum = 0
        for q in xrange(0, value_arg + 1):
            mm = ord(content[offset + q])
            mm <<= 8 * q
            sum |= mm
        # sum += ord(content[offset+q])
        if value_type == 0x17:
            str1 += "\""
            str1 += lex_object.getstringbyid(sum)
            str1 += "\""
        elif value_type == 0x18:
            print "type@%d" % sum,
            str1 += lex_object.gettypename(sum),
        elif value_type == 0x19:
            print "field@%d" % sum,
            str1 += lex_object.getfieldname(sum),
        elif value_type == 0x1a:
            print "method@%d" % sum,
            str1 += lex_object.getmethodname(sum),
        else:
            str2 = ""
            for q in xrange(0, value_arg + 1):
                str2 += "%02x " % (ord(content[offset + q]))
            str1 += str2
        offset += (value_arg + 1)
    elif value_type == 0:
        str1 += "%02x" % ord(content[offset])
        offset += 1

    elif value_type == 0x1e:
        str1 += "NULL"
    elif value_type == 0x1f:
        if value_arg == 0:
            str1 += "false"
        else:
            str1 += "true"
        offset += 0
    elif value_type == 0x1d:
        size, text = parse_encoded_annotation1(lex_object, content[offset:])
        offset += size
        str1 += text
    elif value_type == 0x1c:
        m, asize = get_uleb128(content[offset:5])
        offset += m
        str1 += "[%d]" % asize
        for q in xrange(0, asize):
            size, text = parse_encoded_value1(lex_object, content[offset:], False)
            offset += size
            str1 += text
    else:
        str1 += "***************error parse encode_value**************"
    return offset, str1


def parse_encoded_value4441(lex_object, content, is_root=False):
    offset = 0
    arg_type, = struct.unpack_from("B", content, offset)
    offset += struct.calcsize("B")
    value_arg = arg_type >> 5
    value_type = arg_type & 0x1f
    if value_type in [0x2, 3, 4, 6, 0x10, 0x11, 0x17, 0x18, 0x19, 0x1a, 0x1b]:
        str = ""
        for q in xrange(0, value_arg + 1):
            str += "%02x " % (ord(content[offset + q]))
        print str,
        offset += (value_arg + 1)
    elif value_type == 0:
        print "%02x" % ord(content[offset]),
        offset += 1

    elif value_type == 0x1e:
        print "NULL",
    elif value_type == 0x1f:
        if value_arg == 0:
            print "False",
        else:
            print "True",
        offset += 0
    elif value_type == 0x1d:
        offset += parse_encoded_annotation(lex_object, content[offset:])
    elif value_type == 0x1c:
        m, asize = get_uleb128(content[offset:5 + offset])
        offset += m
        print "[%d]" % asize,
        for q in xrange(0, asize):
            offset += parse_encoded_value(lex_object, content[offset:], False)
    else:
        print "***************error parse encode_value**************"
    return offset


def parse_encoded_annotation1(lex_object, content, is_root=False):
    str1 = ""
    offset = 0
    n, type_idx = get_uleb128(content[offset:5 + offset])
    offset += n
    n, size = get_uleb128(content[offset:5 + offset])
    offset += n
    if is_root:
        str1 += lex_object.gettypenamebyid(type_idx)
    for i in xrange(0, size):
        n, name_idx = get_uleb128(content[offset:5 + offset])
        if i == 0 and is_root:
            str1 += lex_object.getstringbyid(name_idx)
        offset += n
        size, text = parse_encoded_value1(lex_object, content[offset:], is_root)
        offset += size
        str1 += text
    return offset, str1


def parse_encoded_annotation(lex_object, content, is_root=False):
    offset = 0
    n, type_idx = get_uleb128(content[offset:5 + offset])
    offset += n
    n, size = get_uleb128(content[offset:5 + offset])
    offset += n
    if is_root:
        print lex_object.gettypenamebyid(type_idx),
    for i in xrange(0, size):
        n, name_idx = get_uleb128(content[offset:5 + offset])
        if i == 0 and is_root:
            print lex_object.getstringbyid(name_idx),
        offset += n
        offset += parse_encoded_value(lex_object, content[offset:], is_root)
    return offset


def parse_annotation_set_item(lex_object, offset, is_root=False):
    size, = struct.unpack_from("I", lex_object.m_content, offset)
    offset += struct.calcsize("I")
    for i in xrange(0, size):
        off, = struct.unpack_from("I", lex_object.m_content, offset)
        visibility, = struct.unpack_from("B", lex_object.m_content, off)
        if visibility == 0:
            print "VISIBILITY_BUILD",
        elif visibility == 1:
            print "VISIBILITY_RUNTIME",
        elif visibility == 2:
            print "VISIBILITY_SYSTEM",
        else:
            print "visibility is unknow %02x" % visibility
        off += struct.calcsize("B")
        parse_encoded_annotation(lex_object, lex_object.m_content[off:], True)
        offset += struct.calcsize("I")
        print ""


def parse_annotation_set_ref_list(lex_object, offset, is_root=False):
    size, = struct.unpack_from("I", lex_object.m_content, offset)
    offset += struct.calcsize("I")
    for i in xrange(0, size):
        off, = struct.unpack_from("I", lex_object.m_content, offset)
        parse_annotation_set_item(lex_object, off, True)
        offset += struct.calcsize("I")


def get_encoded_field(content):
    n, val1 = get_uleb128(content)
    n1, val2 = get_uleb128(content[n:])
    return n + n1, val1, val2


def get_encoded_method(content):
    n, val1 = get_uleb128(content)
    n1, val2 = get_uleb128(content[n:])
    n2, val3 = get_uleb128(content[n + n1:])
    return n + n1 + n2, val1, val2, val3


class dex_parser:
    def __init__(self, filename):
        global DEX_MAGIC  # dex文件魔术字
        global DEX_OPT_MAGIC  # odex文件魔术字
        self.m_javaobject_id = 0
        self.m_filename = filename  # 得到文件名
        self.m_fd = open(filename, "rb")  # 打开文件
        self.m_content = self.m_fd.read()  # 读取文件的二进制流
        self.m_fd.close()
        self.m_dex_optheader = None
        self.m_class_name_id = {}
        self.string_table = []
        if self.m_content[0:4] == DEX_OPT_MAGIC:  # 把文件的前四个字节用来对比
            self.init_optheader(self.m_content)
            self.init_header(self.m_content, 0x40)
        elif self.m_content[0:4] == DEX_MAGIC:
            self.init_header(self.m_content, 0)
        else:
            print "Please choose a dex or odex file"
            quit()
        bOffset = self.m_stringIdsOff
        if self.m_stringIdsSize > 0:
            for i in xrange(0, self.m_stringIdsSize):
                # 每个字符串的偏移值
                offset, = struct.unpack_from("I", self.m_content, bOffset + i * 4)
                if i == 0:
                    start = offset
                else:
                    skip, length = get_uleb128(
                        self.m_content[start:start + 5])  # 字符串用mutf-8编码 这种编码头部用uleb128编码的字符来表示长度 得到字符串开始的偏移和字符串的长度
                    self.string_table.append(self.m_content[start + skip:offset - 1].replace('\n','\\n'))  # 把字符串加入到table中
                    start = offset
            # 添加最后一个字符串
            for i in xrange(start, len(self.m_content)):
                if self.m_content[i] == chr(0):
                    self.string_table.append(self.m_content[start + 1:i].replace('\n','\\n'))
                    break

        for i in xrange(0, self.m_classDefSize):
            str1 = self.getclassname(i)  # 得到class名
            self.m_class_name_id[str1] = i  # 放到class_name_id表中
        for i in xrange(0, self.m_classDefSize):
            dex_class(self, i).printf(self)
            pass
        # self.getclass(i)

    def create_all_header(self):
        for i in xrange(0, self.m_classDefSize):
            str1 = self.getclassname(i)
            self.create_cpp_header(str1)

    def create_cpp_header(self, classname="Landroid/app/Activity;"):
        if self.m_class_name_id.has_key(classname):
            classid = self.m_class_name_id[classname]
            field_list = dex_class(self, classid).create_header_file_for_cplusplus(self)
        pass

    def getstringbyid(self, stridx):
        if stridx >= self.m_stringIdsSize:
            return ""
        return self.string_table[stridx]

    def getmethodname(self, methodid):
        if methodid >= self.m_methodIdsSize:
            return ""
        offset = self.m_methodIdsOffset + methodid * struct.calcsize("HHI")
        class_idx, proto_idx, name_idx, = struct.unpack_from("HHI", self.m_content, offset)
        return self.string_table[name_idx]

    def getmethodfullname(self, methodid, hidden_classname=False):
        if methodid >= self.m_methodIdsSize:
            return ""
        offset = self.m_methodIdsOffset + methodid * struct.calcsize("HHI")
        class_idx, proto_idx, name_idx, = struct.unpack_from("HHI", self.m_content, offset)
        classname = self.gettypename(class_idx)
        classname = shorty_decode(classname)
        funcname = self.getstringbyid(name_idx)
        if not hidden_classname:
            classname = ""
        return self.getprotofullname(proto_idx, classname, funcname)

    def getmethodfullname1(self, methodid, parameter_list=[], hidden_classname=False):
        if methodid >= self.m_methodIdsSize:
            return ""
        offset = self.m_methodIdsOffset + methodid * struct.calcsize("HHI")
        class_idx, proto_idx, name_idx, = struct.unpack_from("HHI", self.m_content, offset)
        classname = self.gettypename(class_idx)
        classname = shorty_decode(classname)
        funcname = self.getstringbyid(name_idx)
        if not hidden_classname:
            classname = ""
        return self.getprotofullname1(proto_idx, classname, parameter_list, funcname)

    def getfieldname(self, fieldid):
        if fieldid >= self.m_fieldIdsSize:
            return ""
        offset = self.m_fieldIdsOffset + fieldid * struct.calcsize("HHI")
        class_idx, type_idx, name_idx, = struct.unpack_from("HHI", self.m_content, offset)
        return self.string_table[name_idx]

    def getfieldfullname1(self, fieldid):
        if fieldid >= self.m_fieldIdsSize:
            return ""
        offset = self.m_fieldIdsOffset + fieldid * struct.calcsize("HHI")
        class_idx, type_idx, name_idx, = struct.unpack_from("HHI", self.m_content, offset)
        name = self.gettypename(type_idx)
        name = shorty_decode(name)
        index = name.rfind(".")
        fname = self.getstringbyid(name_idx)
        return "%s %s" % (name[index + 1:], fname)

    def getfieldfullname2(self, fieldid):
        if fieldid >= self.m_fieldIdsSize:
            return ""
        offset = self.m_fieldIdsOffset + fieldid * struct.calcsize("HHI")
        class_idx, type_idx, name_idx, = struct.unpack_from("HHI", self.m_content, offset)
        typename = self.gettypename(type_idx)
        typename = shorty_decode(typename)
        fieldname = self.getstringbyid(name_idx)
        return typename, fieldname

    def getfieldfullname(self, fieldid):
        if fieldid >= self.m_fieldIdsSize:
            return ""
        offset = self.m_fieldIdsOffset + fieldid * struct.calcsize("HHI")
        class_idx, type_idx, name_idx, = struct.unpack_from("HHI", self.m_content, offset)
        name = self.gettypename(type_idx)
        name = shorty_decode(name)
        fname = self.getstringbyid(name_idx)
        return "%s %s" % (name, fname)

    def getfieldtypename(self, fieldid):
        if fieldid >= self.m_fieldIdsSize:
            return ""
        offset = self.m_fieldIdsOffset + fieldid * struct.calcsize("HHI")
        class_idx, type_idx, name_idx, = struct.unpack_from("HHI", self.m_content, offset)
        name = self.gettypename(type_idx)
        if name[-1] != ";":
            name = shorty_decode(name)
        return name

    def gettypename(self, typeid):
        if typeid >= self.m_typeIdsSize:
            return ""
        offset = self.m_typeIdsOffset + typeid * struct.calcsize("I")  # 得到类型偏移值
        descriptor_idx, = struct.unpack_from("I", self.m_content, offset)  # 得到在字符串中的id
        return self.string_table[descriptor_idx]

    def getprotoname(self, protoid):
        if protoid >= self.m_protoIdsSize:
            return ""
        offset = self.m_protoIdsOffset + protoid * struct.calcsize("3I")
        shorty_idx, return_type_idx, parameters_off, = struct.unpack_from("3I", self.m_content, offset)
        return self.string_table[shorty_idx]

    def getprotofullname(self, protoid, classname, func_name):
        if protoid >= self.m_protoIdsSize:
            return ""
        offset = self.m_protoIdsOffset + protoid * struct.calcsize("3I")
        shorty_idx, return_type_idx, parameters_off, = struct.unpack_from("3I", self.m_content, offset)
        retname = self.gettypename(return_type_idx)
        retname = shorty_decode(retname)
        retstr = retname + " "
        if len(classname) == 0:
            retstr += "%s(" % func_name
        else:
            retstr += "%s::%s(" % (classname, func_name)
        if parameters_off != 0:
            offset = parameters_off
            size, = struct.unpack_from("I", self.m_content, offset)
            offset += struct.calcsize("I")
            n = 0
            for i in xrange(0, size):
                type_idx, = struct.unpack_from("H", self.m_content, offset)
                offset += struct.calcsize("H")
                arg = self.gettypename(type_idx)
                arg = shorty_decode(arg)
                if n != 0:
                    retstr += ","
                retstr += arg
                n += 1
        retstr += ")"
        return retstr

    def getprotofullname1(self, protoid, classname, parameter_list, func_name):
        index = classname.rfind(".")
        classname = classname[index + 1:]
        if protoid >= self.m_protoIdsSize:
            return ""
        offset = self.m_protoIdsOffset + protoid * struct.calcsize("3I")
        shorty_idx, return_type_idx, parameters_off, = struct.unpack_from("3I", self.m_content, offset)
        retname = self.gettypename(return_type_idx)
        retname = shorty_decode(retname)
        index = retname.rfind(".")
        retname = retname[index + 1:]
        retstr = retname + " "
        # if len(classname)==0:
        retstr += "%s(" % func_name
        # else:
        #	retstr +=  "%s::%s("%(classname,func_name)
        param_count = len(parameter_list)
        if parameters_off != 0:
            offset = parameters_off
            size, = struct.unpack_from("I", self.m_content, offset)
            offset += struct.calcsize("I")
            n = 0
            for i in xrange(0, size):
                type_idx, = struct.unpack_from("H", self.m_content, offset)
                offset += struct.calcsize("H")
                arg = self.gettypename(type_idx)
                arg = shorty_decode(arg)
                if n != 0:
                    retstr += ","
                index = arg.rfind(".")
                arg = arg[index + 1:]
                retstr += arg
                if i < param_count:
                    retstr += " "
                    retstr += parameter_list[i]
                n += 1
        retstr += ")"
        return retstr

    def getclassmethod_count(self, classid):
        if classid >= self.m_classDefSize:
            return ""
        offset = self.m_classDefOffset + classid * struct.calcsize("8I")
        class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off, = struct.unpack_from(
            "8I", self.m_content, offset)
        if class_data_off:
            offset = class_data_off
            n, static_fields_size = get_uleb128(self.m_content[offset:])
            offset += n
            n, instance_fields_size = get_uleb128(self.m_content[offset:])
            offset += n
            n, direct_methods_size = get_uleb128(self.m_content[offset:])
            offset += n
            n, virtual_methods_size = get_uleb128(self.m_content[offset:])
            offset += n
            return static_fields_size + instance_fields_size
        return 0

    def getclassmethod(classid, method_idx):
        count = 0
        if classid >= self.m_classDefSize:
            return ""
        offset = self.m_classDefOffset + classid * struct.calcsize("8I")
        class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off, = struct.unpack_from(
            "8I", self.m_content, offset)
        if class_data_off:
            offset = class_data_off
            n, static_fields_size = get_uleb128(self.m_content[offset:])
            offset += n
            n, instance_fields_size = get_uleb128(self.m_content[offset:])
            offset += n
            n, direct_methods_size = get_uleb128(self.m_content[offset:])
            offset += n
            n, virtual_methods_size = get_uleb128(self.m_content[offset:])
            offset += n
            count = direct_methods_size + virtual_methods_size
        if method_idx >= count:
            return ""
        ncount = static_fields_size + instance_fields_size
        ncount *= 2
        for i in xrange(0, ncount):
            n, tmp = get_uleb128(self.m_content[offset:])
            offset += n
        ncount *= 3
        for i in xrange(0, ncount):
            n, tmp = get_uleb128(self.m_content[offset:])
            offset += n
        n, method_idx_diff = get_uleb128(self.m_content[offset:])
        offset += n
        n, access_flags = get_uleb128(self.m_content[offset:])
        offset += n
        n, code_off = get_uleb128(self.m_content[offset:])

    def getclassname(self, classid):
        if classid >= self.m_classDefSize:
            return ""
        offset = self.m_classDefOffset + classid * struct.calcsize("8I")  # 得到classdef的偏移
        class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off, = struct.unpack_from(
            "8I", self.m_content, offset)  # 给每个成员赋值
        return self.gettypename(class_idx)  # 通过类型表获取名称

    def init_optheader(self, content):
        offset = 0
        format = "4s"
        self.m_magic, = struct.unpack_from(format, content, offset)
        format = "I"
        offset += struct.calcsize(format)
        self.m_version, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dexOffset, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_dexLength, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_depsOffset, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_depsLength, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_optOffset, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_optLength, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_flags, = struct.unpack_from(format, content, offset)
        offset += struct.calcsize(format)
        self.m_checksum, = struct.unpack_from(format, content, offset)

    def init_header(self, content, offset):
        # 前面之所以需要给format赋值，主要是因为需要类型转换
        format = "4s"
        self.m_magic, = struct.unpack_from(format, content, offset)  # 前四个字节 得到
        format = "I"
        offset += struct.calcsize(format)  # 偏移加四个字节
        self.m_version, = struct.unpack_from(format, content, offset)  # 得到版本号
        offset += struct.calcsize(format)
        self.m_checksum, = struct.unpack_from(format, content, offset)  # 得到校验码
        format = "20s"
        offset += struct.calcsize(format)
        self.m_signature, = struct.unpack_from(format, content, offset)  # 得到签名
        format = "I"
        offset += struct.calcsize(format)
        self.m_fileSize, = struct.unpack_from(format, content, offset)  # 得到文件大小
        offset += struct.calcsize(format)
        self.m_headerSize, = struct.unpack_from(format, content, offset)  # 得到文件头长度 0x35版本这个值总为0x70
        offset += struct.calcsize(format)
        self.m_endianTag, = struct.unpack_from(format, content, offset)  # 表示字节顺序的常量
        offset += struct.calcsize(format)
        self.m_linkSize, = struct.unpack_from(format, content, offset)  # 链接段的大小
        offset += struct.calcsize(format)
        self.m_linkOff, = struct.unpack_from(format, content, offset)  # 链接段的偏移
        offset += struct.calcsize(format)
        self.m_mapOffset, = struct.unpack_from(format, content, offset)  # Map段的偏移
        offset += struct.calcsize(format)
        self.m_stringIdsSize, = struct.unpack_from(format, content, offset)  # 字符串列表的中字符串的个数
        offset += struct.calcsize(format)
        self.m_stringIdsOff, = struct.unpack_from(format, content, offset)  # 字符串列表的偏移
        offset += struct.calcsize(format)
        self.m_typeIdsSize, = struct.unpack_from(format, content, offset)  # 类型列表中类型的个数
        offset += struct.calcsize(format)
        self.m_typeIdsOffset, = struct.unpack_from(format, content, offset)  # 类型列表的偏移
        offset += struct.calcsize(format)
        self.m_protoIdsSize, = struct.unpack_from(format, content, offset)  # 原型列表中原型的个数
        offset += struct.calcsize(format)
        self.m_protoIdsOffset, = struct.unpack_from(format, content, offset)  # 原型列表的偏移
        offset += struct.calcsize(format)
        self.m_fieldIdsSize, = struct.unpack_from(format, content, offset)  # 字段列表中字段的个数
        offset += struct.calcsize(format)
        self.m_fieldIdsOffset, = struct.unpack_from(format, content, offset)  # 字段列表的偏移
        offset += struct.calcsize(format)
        self.m_methodIdsSize, = struct.unpack_from(format, content, offset)  # 方法列表中方法的个数
        offset += struct.calcsize(format)
        self.m_methodIdsOffset, = struct.unpack_from(format, content, offset)  # 方法列表的偏移
        offset += struct.calcsize(format)
        self.m_classDefSize, = struct.unpack_from(format, content, offset)  # 类定义列表中类的个数
        offset += struct.calcsize(format)
        self.m_classDefOffset, = struct.unpack_from(format, content, offset)  # 类定义列表的偏移
        offset += struct.calcsize(format)
        self.m_dataSize, = struct.unpack_from(format, content, offset)  # 数据段的大小，必须4字节对齐
        offset += struct.calcsize(format)
        self.m_dataOff, = struct.unpack_from(format, content, offset)  # 数据段的偏移

    # 根据类型的id得到类型名
    def gettypenamebyid(self, typeid):
        if typeid >= self.m_typeIdsSize:
            return ""
        offset = self.m_typeIdsOffset + typeid * struct.calcsize("I")
        descriptor_idx, = struct.unpack_from("I", self.m_content, offset)
        return self.string_table[descriptor_idx]

    def get_access_flags(self, flags):
        val = {1: "public",
               2: "private",
               4: "protected",
               8: "static",
               0x10: "final",
               0x20: "synchronized",
               0x40: "volatile",
               0x80: "bridge",
               0x100: "native",
               0x200: "interface",
               0x400: "abstract",
               0x800: "strict",
               0x1000: "synthetic",
               0x2000: "annotation",
               0x4000: "enum",
               0x8000: "unused",
               0x10000: "constructor",
               0x20000: "declared_synchronized"
               }
        value = ""
        i = 0
        for key in val:
            if key & flags:
                if i != 0:
                    value += " "
                value += val[key]
                i += 1
        if i == 0:
            value += "public "

        return value

    def get_access_flags1(self, flags):
        val = {1: "public",
               2: "private",
               4: "protected"
               }
        value = ""
        i = 0
        for key in val:
            if key & flags:
                if i != 0:
                    value += " "
                value += val[key]
                i += 1
        if i == 0:
            value += "public"
            flags = 1

        return value + ":", flags


def main():
    if len(sys.argv) < 2:
        print "Usages: %s dex_file" % sys.argv[0]
        quit()
    filename = sys.argv[1]
    dex = dex_parser(filename)


if __name__ == "__main__":
    main()
