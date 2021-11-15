import binascii
import sys

checksum = 0
signature = 0
file_size = 0
endian_tag = 0
link_size = 0
link_off = 0
map_off = 0
string_ids_size = 0
string_ids_off = 0
type_ids_size = 0
type_ids_off = 0
proto_ids_size = 0
proto_ids_off = 0
field_ids_size = 0
field_ids_off = 0
method_ids_size = 0
method_ids_off = 0
class_defs_size = 0
class_defs_off = 0
data_size = 0
data_off = 0

def parse_header(dex, out: bool):
	dex.seek(8)
	global checksum
	checksum = hex(int.from_bytes(dex.read(4), byteorder="little"))
	if out : print("Checksum: {}".format(checksum))

	dex.seek(0xC)
	global signature
	signature = hex(int.from_bytes(dex.read(20), byteorder="little"))
	if out : print("Signature: {}".format(signature))

	dex.seek(0x20)
	global file_size
	file_size = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("File size: {}".format(file_size))

	dex.seek(0x24)
	global header_size
	header_size = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Header size: {}".format(header_size))

	dex.seek(0x28)
	global endian_tag
	endian_tag = hex(int.from_bytes(dex.read(4), byteorder="little"))
	if out : print("Endian tag: {}".format(endian_tag))

	dex.seek(0x2C)
	global link_size
	link_size = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Link size: {}".format(link_size))

	dex.seek(0x30)
	global link_off
	link_off = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Link off: {}".format(link_off))

	dex.seek(0x34)
	global map_off
	map_off = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Map off: {}".format(map_off))

	dex.seek(0x38)
	global string_ids_size
	string_ids_size = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("String ids size: {}".format(string_ids_size))
	
	dex.seek(0x3C)
	global string_ids_off
	string_ids_off = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("String ids off: {}".format(string_ids_off))

	dex.seek(0x40)
	global type_ids_size
	type_ids_size = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Type ids size: {}".format(type_ids_size))
	
	dex.seek(0x44)
	global type_ids_off
	type_ids_off = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Type ids off: {}".format(type_ids_off))

	dex.seek(0x48)
	global proto_ids_size
	proto_ids_size = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Proto ids size: {}".format(proto_ids_size))

	dex.seek(0x4C)
	global proto_ids_off
	proto_ids_off = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Proto ids off: {}".format(proto_ids_off))

	dex.seek(0x50)
	global field_ids_size
	field_ids_size = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Method ids size: {}".format(field_ids_size))

	dex.seek(0x54)
	global field_ids_off
	field_ids_off = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Field ids off: {}".format(field_ids_off))

	dex.seek(0x58)
	global method_ids_size
	method_ids_size = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Method ids size: {}".format(method_ids_size))

	dex.seek(0x5C)
	global method_ids_off
	method_ids_off = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Method ids off: {}".format(method_ids_off))

	dex.seek(0x60)
	global class_defs_size
	class_defs_size = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Class defs size: {}".format(class_defs_size))

	dex.seek(0x64)
	global class_defs_off
	class_defs_off = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Class defs off: {}".format(class_defs_off))

	dex.seek(0x68)
	global data_size
	data_size = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Data size: {}".format(data_size))

	dex.seek(0x6C)
	global data_off
	data_off = int.from_bytes(dex.read(4), byteorder="little")
	if out : print("Data off: {}".format(data_off))

def get_string(dex, index):
	global string_ids_size
	global string_ids_off
	global data_size
	global data_off

	dex.seek(string_ids_off)
	string_ids = dex.read(string_ids_size * 4)
	dex.seek(data_off)
	data = dex.read(data_size)

	data_id = int(string_ids[index * 4]) + (int(string_ids[index * 4 + 1]) << 8) + (int(string_ids[index * 4 + 2]) << 16) + (int(string_ids[index * 4 + 3]) << 32)
	length = int(data[data_id - data_off]) + 1

	ret = str()

	for i in range(1, length):
		ret += chr(data[data_id - data_off + i])
	
	return ret

def get_type(dex, index):
	global type_ids_size, type_ids_off

	dex.seek(type_ids_off)
	type_ids = dex.read(type_ids_size * 4)

	string_id = int(type_ids[index * 4]) + (int(type_ids[index * 4 + 1]) << 8) + (int(type_ids[index * 4 + 2]) << 16) + (int(type_ids[index * 4 + 3]) << 32)

	return get_string(dex, string_id)

def get_proto(dex, index):
	global proto_ids_size, proto_ids_off

	dex.seek(proto_ids_off)
	proto_ids = dex.read(proto_ids_size * 12)

	return_type_idx = int(proto_ids[index * 12 + 4]) + int(proto_ids[index * 12 + 5] << 8) + int(proto_ids[index * 12 + 6] << 16) + int(proto_ids[index * 12 + 7] << 32)
	parameters_off = int(proto_ids[index * 12 + 8]) + int(proto_ids[index * 12 + 9] << 8) + int(proto_ids[index * 12 + 10] << 16) + int(proto_ids[index * 12 + 11] << 32)

	if parameters_off:
		result = get_type(dex, return_type_idx) + "("
		dex.seek(parameters_off)
		paramenters_number = int.from_bytes(dex.read(4), byteorder="little")
		dex.seek(parameters_off + 4)
		paramenters_list = dex.read(paramenters_number * 2)
		for i in range(0, paramenters_number):
			paramenters_idx = int(paramenters_list[i * 2]) + int(paramenters_list[i * 2 + 1] << 8)
			result += get_type(dex, paramenters_idx)
		result += ")"
	else:
		result = get_type(dex, return_type_idx) + "()"

	return result

def get_field(dex, index):
	global field_ids_size, field_ids_off

	dex.seek(field_ids_off)
	field_ids = dex.read(field_ids_size * 8)

	class_idx = int(field_ids[index * 8]) + int(field_ids[index * 8 + 1] << 8)
	type_idx = int(field_ids[index * 8 + 2]) + int(field_ids[index * 8 + 3] << 8)
	name_idx = int(field_ids[index * 8 + 4]) + int(field_ids[index * 8 + 5] << 8) + int(field_ids[index * 8 + 6] << 16) + int(field_ids[index * 8 + 7] << 32)
	return class_idx, type_idx, name_idx

def get_method(dex, index):
	global method_ids_size, method_ids_off

	dex.seek(method_ids_off)
	method_ids = dex.read(method_ids_size * 8)

	class_idx = int(method_ids[index * 8]) + int(method_ids[index * 8 + 1] << 8)
	proto_idx = int(method_ids[index * 8 + 2]) + int(method_ids[index * 8 + 3] << 8)
	name_idx = int(method_ids[index * 8 + 4]) + int(method_ids[index * 8 + 5] << 8) + int(method_ids[index * 8 + 6] << 16) + int(method_ids[index * 8 + 7] << 32)
	return get_string(dex, name_idx), get_type(dex, class_idx), get_proto(dex, proto_idx)

def get_code(dex, code_off):
	global data_size, data_off 

	dex.seek(0)
	data = dex.read()

	return data[code_off :]

def parse_string(dex):
	global string_ids_size, string_ids_off
	global data_size, data_off

	dex.seek(string_ids_off)
	string_ids = dex.read(string_ids_size * 4)
	dex.seek(data_off)
	data = dex.read(data_size)

	for index in range(0, string_ids_size):
		data_id = int(string_ids[index * 4]) + (int(string_ids[index * 4 + 1]) << 8) + (int(string_ids[index * 4 + 2]) << 16) + (int(string_ids[index * 4 + 3]) << 32)
		length = int(data[data_id - data_off])

		for i in range(0, length + 1):
			print(chr(int(data[data_id - data_off + i])), end="")
		print("")

def parse_type(dex):
	global type_ids_size, type_ids_off

	dex.seek(type_ids_off)
	type_ids = dex.read(type_ids_size * 4)

	string_id = 0
	for index in range(0, type_ids_size):
		string_id = int(type_ids[index * 4]) + (int(type_ids[index * 4 + 1]) << 8) + (int(type_ids[index * 4 + 2]) << 16) + (int(type_ids[index * 4 + 3]) << 32)
		get_string(dex, index)

	return None

def parse_proto(dex):
	global proto_ids_size, proto_ids_off

	dex.seek(proto_ids_off)
	proto_ids = dex.read(proto_ids_size * 12)

	string_id = 0
	for index in range(0, proto_ids_size):
		shorty_idx = int(proto_ids[index * 12]) + int(proto_ids[index * 12 + 1] << 8) + int(proto_ids[index * 12 + 2] << 16) + int(proto_ids[index * 12 + 3] << 32)
		return_type_idx = int(proto_ids[index * 12 + 4]) + int(proto_ids[index * 12 + 5] << 8) + int(proto_ids[index * 12 + 6] << 16) + int(proto_ids[index * 12 + 7] << 32)
		parameters_off = int(proto_ids[index * 12 + 8]) + int(proto_ids[index * 12 + 9] << 8) + int(proto_ids[index * 12 + 10] << 16) + int(proto_ids[index * 12 + 11] << 32)
		print("shorty_idx:", get_string(dex, shorty_idx),
				"return_type_idx:", get_type(dex, return_type_idx))

		if parameters_off != 0:
			dex.seek(parameters_off)
			paramenters_number = int.from_bytes(dex.read(4), byteorder="little")
			dex.seek(parameters_off + 4)
			paramenters_list = dex.read(paramenters_number * 2)
			for i in range(0, paramenters_number):
				paramenters_idx = int(paramenters_list[i * 2]) + int(paramenters_list[i * 2 + 1] << 8)
				print("paramenters_idx", i, ":", get_type(dex, paramenters_idx))
		print("")

	return None

def parse_field(dex):
	global field_ids_size, field_ids_off

	dex.seek(field_ids_off)
	field_ids = dex.read(field_ids_size * 8)

	for index in range(0, field_ids_size):
		class_idx = int(field_ids[index * 8]) + int(field_ids[index * 8 + 1] << 8)
		type_idx = int(field_ids[index * 8 + 2]) + int(field_ids[index * 8 + 3] << 8)
		name_idx = int(field_ids[index * 8 + 4]) + int(field_ids[index * 8 + 5] << 8) + int(field_ids[index * 8 + 6] << 16) + int(field_ids[index * 8 + 7] << 32)
		print("file_name:", get_string(dex, name_idx))
		print("class_idx:", get_type(dex, class_idx))
		print("type_idx:", get_type(dex, type_idx))
		print("")

def parse_method(dex):
	global method_ids_size, method_ids_off

	dex.seek(method_ids_off)
	method_ids = dex.read(method_ids_size * 8)

	string_id = 0
	for index in range(0, method_ids_size):
		class_idx = int(method_ids[index * 8]) + int(method_ids[index * 8 + 1] << 8)
		proto_idx = int(method_ids[index * 8 + 2]) + int(method_ids[index * 8 + 3] << 8)
		name_idx = int(method_ids[index * 8 + 4]) + int(method_ids[index * 8 + 5] << 8) + int(method_ids[index * 8 + 6] << 16) + int(method_ids[index * 8 + 7] << 32)
		print("method_name:", get_string(dex, name_idx))
		print("class_idx:", get_type(dex, class_idx))
		print("proto_idx:", get_proto(dex, proto_idx))
		print("")

def parse_acces_flags(flag):
	result = ""

	if flag & 0x1:
		result += "public "
	if flag & 0x2:
		result += "private "
	if flag & 0x4:
		result += "protected"
	if flag & 0x8:
		result += "static "
	if flag & 0x10:
		result += "final "
	if flag & 0x20:
		result += "synchronized "
	if flag & 0x40:
		result += "volatile "
	if flag & 0x80:
		result += "transient "
	if flag & 0x100:
		result += "native "
	if flag & 0x200:
		result += "interface "
	if flag & 0x400:
		result += "abstract "
	if flag & 0x800:
		result += "strictfp "
	if flag & 0x1000:
		result += "synthetic "
	if flag & 0x2000:
		result += "annotation "
	if flag & 0x4000:
		result += "enum "
	if flag & 0x10000:
		result += "constructor "
	if flag & 0x20000:
		result += "synchronized "

	return result

def uledb128_decode(content, offset):
	size = 1

	result = content[offset]
	if (result > 0x7f):
		cur = content[offset + 1]
		result = (result & 0x7f) | ((cur & 0x7f) << 7)
		size += 1
		if (cur > 0x7f):
			cur = content[offset + 2]
			result |= (cur & 0x7f) << 14
			size += 1
			if (cur > 0x7f):
				cur = content[offset + 3]
				result |= (cur & 0x7f) << 21
				size += 1
				if (cur > 0x7f):
					cur = content[offset + 4]
					result |= cur << 28
					size += 1

	return (result, size)

def parse_class(dex):
	global class_defs_size, class_defs_off
	global data_size, data_off

	dex.seek(class_defs_off)
	class_defs = dex.read(class_defs_size * 0x20)

	string_id = 0
	for index in range(0, class_defs_size):
		class_idx = int.from_bytes(class_defs[index * 0x20 : index * 0x20 + 3], byteorder="little")
		access_flags = int.from_bytes(class_defs[index * 0x20 + 4 : index * 0x20 + 7], byteorder="little")
		superclass_idx = int.from_bytes(class_defs[index * 0x20 + 8 : index * 0x20 + 11], byteorder="little")
		interfaces_off = int.from_bytes(class_defs[index * 0x20 + 12 : index * 0x20 + 15], byteorder="little")
		source_file_idx = int.from_bytes(class_defs[index * 0x20 + 16 : index * 0x20 + 19], byteorder="little")
		class_data_off = int.from_bytes(class_defs[index * 0x20 + 24 : index * 0x20 + 27], byteorder="little")
		print("class_name:", get_type(dex, class_idx))
		print("access_flags:", parse_acces_flags(access_flags))
		print("superclass_idx:", get_type(dex, superclass_idx))
		if interfaces_off:
			dex.seek(interfaces_off)
			interfaces_size = int.from_bytes(dex.read(4), byteorder='little')
			interfaces_list = dex.read(interfaces_size * 2)
			for i in range(0, interfaces_size):
				interfaces_index = int.from_bytes(interfaces_list[i * 2 : i * 2 + 2], byteorder='little')
				print("interfaces_list:", i, get_type(dex, interfaces_index))
		print("source_file", get_string(dex, source_file_idx))

		dex.seek(data_off)
		data = dex.read(data_size)
		
		static_field_size = int(data[class_data_off - data_off])
		instance_fields_size = int(data[class_data_off - data_off + 1])
		direct_methods_size = int(data[class_data_off - data_off + 2])
		virtual_methods_size = int(data[class_data_off - data_off + 3])

		print("static_field_size:", static_field_size)
		print("instance_fields_size:", instance_fields_size)
		print("direct_methods_size:", direct_methods_size)
		print("virtual_methods_size:", virtual_methods_size)

		offset = 0
		result = []
		static_result = []
		static_offset = 0
		instance_result = []
		instance_offset = 0
		direct_result = []
		direct_offset = 0
		virtual_result = []
		virtual_offset = 0

		for i in range(0, static_field_size * 2):
			result = 0
			offset = 0
			result, offset = uledb128_decode(data[class_data_off - data_off + 4:], static_offset)
			static_offset += offset
			static_result.append(result)
		
		for i in range(0, instance_fields_size * 2):
			result = 0
			offset = 0
			result, offset = uledb128_decode(data[class_data_off - data_off + 4 + static_offset:], instance_offset)
			instance_offset += offset
			instance_result.append(result)

		for i in range(0, direct_methods_size * 3):
			result = 0
			offset = 0
			result, offset = uledb128_decode(data[class_data_off - data_off + 4 + static_offset + instance_offset:], direct_offset)
			direct_offset += offset
			direct_result.append(result)

		for i in range(0, virtual_methods_size * 3):
			result = 0
			offset = 0
			result, offset = uledb128_decode(data[class_data_off - data_off + 4 + static_offset + instance_offset + direct_offset:], virtual_offset)
			virtual_offset += offset
			virtual_result.append(result)

		for i in range(0, static_field_size):
			filed_idx_diff = static_result[i * 2]
			access_flags = static_result[i * 2 + 1]
			class_idx, type_idx, name_idx= get_field(dex, filed_idx_diff)
			filed_name = get_string(dex, name_idx)
			class_name = get_type(dex, class_idx)
			type_name = get_type(dex, type_idx)
			print("static_fields", i, ":", parse_acces_flags(access_flags), type_name, class_name, filed_name)

		for i in range(0, instance_fields_size):
			field_idx_diff = instance_result[i * 2]
			access_flags = instance_result[i * 2 + 1]
			class_idx, type_idx, name_idx= get_field(dex, filed_idx_diff)
			filed_name = get_string(dex, name_idx)
			class_name = get_type(dex, class_idx)
			type_name = get_type(dex, type_idx)
			print("instance_field", i, ":", parse_acces_flags(access_flags), type_name, class_name, filed_name)
		
		for i in range(0, direct_methods_size):
			method_idx_diff = direct_result[i * 3]
			access_flags = direct_result[i * 3 + 1]
			code_off = direct_result[i * 3 + 2]
			method_name, class_name, proto_name = get_method(dex, method_idx_diff)
			print("direct_methods_size", i, ":", parse_acces_flags(access_flags), class_name, method_name, proto_name)
			code = get_code(dex, code_off)
			registers_size = int.from_bytes(code[0:2], byteorder='little')
			ins_size = int.from_bytes(code[2:4], byteorder='little')
			outs_size = int.from_bytes(code[4:6], byteorder='little')
			tries_size = int.from_bytes(code[6:8], byteorder='little')
			debug_info_off = int.from_bytes(code[8:12], byteorder='little')
			insns_size = int.from_bytes(code[12:16], byteorder='little')
			insns = code[16:16 + insns_size]
			print("registers_size:", registers_size)
			print("ins_size:", ins_size)
			print("outs_size:", outs_size)
			print("tries_size:", tries_size)
			print("debug_info_off:", debug_info_off)
			print("insns_size:", insns_size)
			print("insns:", insns)
		print("")

def main(argv: list):
	if len(argv) < 2:
		print("Usage: {} <dexfile>".format(argv[0]))
		return 1

	with open(argv[1], "rb+") as dex:
		magic = dex.read(8)
		if (magic != b"dex\n035\0"):
			print("Invalid dex file")
			return 1
		
		if argv[2] == "-h":
			parse_header(dex, True)
		else:
			parse_header(dex, False)

		if argv[2] == "-s":
			parse_string(dex)

		if argv[2] == "-t":
			parse_type(dex)
		
		if argv[2] == "-p":
			parse_proto(dex)
		
		if argv[2] == "-f":
			parse_field(dex)
		
		if argv[2] == "-m":
			parse_method(dex)
		
		if argv[2] == "-c":
			parse_class(dex)

if __name__ == "__main__":
	main(sys.argv)