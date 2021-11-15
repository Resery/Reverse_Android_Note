checksum = 0
signature = 0
string_ids_size = 0
string_ids_off = 0
type_ids_size = 0
type_ids_off = 0
method_ids_size = 0
method_ids_off = 0
class_defs_size = 0
class_defs_off = 0
data_size = 0
data_off = 0

def parse_header(dex):
	dex.seek(0x8)
	global checksum
	checksum = int.from_bytes(dex.read(4), byteorder="little")

	dex.seek(0xC)
	global signature
	signature = int.from_bytes(dex.read(20), byteorder="little")

	dex.seek(0x38)
	global string_ids_size
	string_ids_size = int.from_bytes(dex.read(4), byteorder="little")
	
	dex.seek(0x3C)
	global string_ids_off
	string_ids_off = int.from_bytes(dex.read(4), byteorder="little")

	dex.seek(0x40)
	global type_ids_size
	type_ids_size = int.from_bytes(dex.read(4), byteorder="little")
	
	dex.seek(0x44)
	global type_ids_off
	type_ids_off = int.from_bytes(dex.read(4), byteorder="little")

	dex.seek(0x58)
	global method_ids_size
	method_ids_size = int.from_bytes(dex.read(4), byteorder="little")

	dex.seek(0x5C)
	global method_ids_off
	method_ids_off = int.from_bytes(dex.read(4), byteorder="little")

	dex.seek(0x60)
	global class_defs_size
	class_defs_size = int.from_bytes(dex.read(4), byteorder="little")

	dex.seek(0x64)
	global class_defs_off
	class_defs_off = int.from_bytes(dex.read(4), byteorder="little")

	dex.seek(0x68)
	global data_size
	data_size = int.from_bytes(dex.read(4), byteorder="little")

	dex.seek(0x6C)
	global data_off
	data_off = int.from_bytes(dex.read(4), byteorder="little")

def get_string(dex, index):
	global string_ids_size, string_ids_off

	data = dex.read()
	dex.seek(string_ids_off)
	string_buf = dex.read(string_ids_size * 4)
	data_id = int.from_bytes(string_buf[index * 4 : index * 4 + 4], byteorder="little")

	dex.seek(data_id)
	string_length = int.from_bytes(dex.read(1), byteorder="little")
	dex.seek(data_id + 1)
	string = dex.read(string_length).decode("utf-8")

	return string

def get_method(dex, index):
	global method_ids_size, method_ids_off

	data = dex.read()
	dex.seek(method_ids_off)
	method_buf = dex.read(method_ids_size * 8)
	method_name_id = int.from_bytes(method_buf[index * 8 + 4: index * 8 + 8], byteorder="little") 

	return (get_string(dex, method_name_id))

def get_type(dex, index):
	global type_ids_size, type_ids_off

	data = dex.read()
	dex.seek(type_ids_off)
	type_buf = dex.read(type_ids_size * 4)
	stirng_idx = int.from_bytes(type_buf[index * 4 : index * 4 + 4], byteorder="little")

	return get_string(dex, stirng_idx)

def get_class(dex, index):
	global class_defs_size, class_defs_off

	dex.seek(class_defs_off)
	class_buf = dex.read(class_defs_size * 0x20)

	class_idx = int.from_bytes(class_buf[index * 0x20 : index * 0x20 + 4], byteorder="little")
	return get_type(dex, class_idx)

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

def calc(buf):
	varA = 1 
	varB = 0 
	result = []

	for i in range(0, len(buf)):
		varA = (varA + buf[i]) % 65521
		varB = (varB + varA) % 65521
	
	result.append(varA)
	result.append(varB)

	return result 

def restore_checksum(buf):
	varList = calc(buf[12:])
	checksum = (varList[1] << 16) + varList[0]
	first_byte = checksum & 0xFF
	second_byte = (checksum >> 8) & 0xFF
	third_byte = (checksum >> 16) & 0xFF
	forth_byte = (checksum >> 24) & 0xFF

	buf[8] = first_byte
	buf[9] = second_byte
	buf[10] = third_byte
	buf[11] = forth_byte

def restore_sign(buf):
	import hashlib
	sourceData = buf[12:32]
	sha1 = hashlib.sha1()
	sha1.update(buf[32:])
	sha0 = sha1.hexdigest
	sha2 = sha1.digest()
	for i in range(0, 20):
		buf[12 + i] = sha2[i]

def restore_checksum_signature(buf):
	restore_sign(buf)
	restore_checksum(buf)

def main():
	extract_class_name = "Lcom/example/androiddemo/Activity/LoginActivity;"
	extract_method_name = "a"

	with open("./extract/classes.dex", "rb") as dex:
		parse_header(dex)

		for index in range(0, class_defs_size):
			if extract_class_name == get_class(dex, index):

				dex.seek(class_defs_off)
				class_buf = dex.read(class_defs_size * 0x20)
				class_data_off = int.from_bytes(class_buf[index * 0x20 + 24: index * 0x20 + 28],
												byteorder = "little")
				
				dex.seek(0)
				data = dex.read()

				static_field_size = int(data[class_data_off])
				instance_field_size = int(data[class_data_off + 1])
				direct_methods_size = int(data[class_data_off + 2])

				static_offset = 0
				instance_offset = 0
				direct_offset = 0
				direct_result = []

				for i in range(0, static_field_size * 2):
					offset = 0
					_, offset = uledb128_decode(data[class_data_off + 4:], static_offset)
					static_offset += offset
		
				for i in range(0, instance_field_size * 2):
					offset = 0
					_, offset = uledb128_decode(data[class_data_off + 4 + static_offset:], instance_offset)
					instance_offset += offset

				for i in range(0, direct_methods_size * 3):
					result = 0
					offset = 0
					result, offset = uledb128_decode(data[class_data_off + 4 + static_offset + instance_offset:], direct_offset)
					direct_offset += offset
					direct_result.append(result)

				method_idx_off_buf = []
				for index in range(0, direct_methods_size):
					method_idx_off_buf.append(int(direct_result[index * 3]))

				found_index = []
				for index in range(0, len(method_idx_off_buf)):
					if method_idx_off_buf[index] == 1:
						method_idx_off_buf[index] = method_idx_off_buf[index - 1] + 1 
					if extract_method_name ==  get_method(dex, method_idx_off_buf[index]):
						found_index.append(index)
				
				hacked_buf = []
				dex.seek(0)
				hacked_buf = bytearray(dex.read())
				with open("./extract/hacked.dex", "wb+") as hacked_dex:
					for index in found_index:
						code_off = int(direct_result[index * 3 + 2])
						insns_size = hacked_buf[code_off + 12]
						code = hacked_buf[code_off + 16: code_off + 16 + insns_size * 2]
						with open("./extract/restore{}.code".format(found_index.index(index)), "wb") as restore_code:
							restore_code.write(code)
						for i in range(code_off + 16, code_off + 16 + insns_size * 2):
							hacked_buf[i] = 0
					restore_checksum_signature(hacked_buf)
					hacked_dex.write(hacked_buf)
				break

if __name__ == "__main__":
	main()