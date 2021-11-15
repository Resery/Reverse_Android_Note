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
	checksum = hex(int.from_bytes(dex.read(4), byteorder="little"))

	dex.seek(0xC)
	global signature
	signature = hex(int.from_bytes(dex.read(20), byteorder="little"))

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
	data_id = int.from_bytes(strings[index : index + 4], byteorder="little")

	dex.seek(data_off + data_id)
	string_length = dex.read(1)
	string = data[data_off + data_id + 1 : data_off + data_id + 1 + string_length]

	return string



def main():
	extract_class_name = ""
	extract_method_name = ""

	with open("./extract/classes.dex", "rb") as dex:
		parse_header(dex)

		print(get_string(dex, 0x5))

	return None

if __name__ == "__main__":
	main()