# Functions and inspiration from https://github.com/threatexpress/random_c2_profile <3
import random
import string
from core.htmlcontent import contents
from core.objects import objects

class format:
	def getRandomByteArray(length):
		low = 80
		high = 255
		result = ""
		for i in range(length):
			h = random.randint(low,high)
			hh = bytearray([h]).hex()
			result += '\\x' + hh
		return str(result)

	def getRandomString(length):
		letters = string.ascii_uppercase
		result_str = ''.join(random.choice(letters) for i in range(length))
		return result_str

	def getRandomAlphanum(length):
		alphanum = string.ascii_uppercase + string.digits
		result_str = ''.join(random.choice(alphanum) for i in range(length))
		return str(result_str)

class dynamic:
	def httpsCert(input):
		if input == 'true':
			selfsigned = """  set C   "US";
    set CN  "Amazon";
    set O   "Amazon";
    set OU  "Server CA 1B";
    set validity "365";"""
			return selfsigned
		else:
			datastored = """  set keystore "domain.store";
    set password "mypassword";"""
			return datastored

	def randomFrameHeader(type, input):
		if input == 'true':
			length = random.randint(5,35)
			result = format.getRandomByteArray(length)
			return "set " + type + " \"" + result + "\";"
		else:
			return ""

	def getHttpContent():
		escaped = random.choice(contents).replace("\\","\\\\").replace('"','\\"')
		content = ''.join(char for char in escaped if ord(char) < 128)
		return content

	def getStageMagicMz86():
		codes = [
			'H@KC', # ASM = dec eax, inc eax, dec ebx, inc ebx
			'KCKC', # ASM = dec ebx, inc ebx, dec ebx, inc ebx
			'@H@H', # ASM = inc eax, dec eax, inc eax, dec eax
			']U]U', # ASM = pop ebp, push ebp, pop ebp, push ebp
			'MEME'  # ASM = inc ebp, dec ebp, inc ebp, dec ebp
			]
		return random.choice(codes)

	def getStageMagicMz64():
		codes = [
			'AXAP', # ASM = pop r8, push r8
			'AYAQ', # ASM = pop r9, push r9
			'AZAR', # ASM = pop r10, push r10
			'^V',   # ASM = pop rsi, push rsi
			'A[AS' # ASM = pop r11, push r11
			]
		return random.choice(codes)

	def getStageMagicPe():
		return format.getRandomString(2)

	def getStageCompileTime():
		month  = random.choice(['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'])
		day    = str(random.randint(1,30)).zfill(2)
		year   = str(random.choice(range(2005,2022)))
		hour   = str(random.randint(1,23)).zfill(2)
		minute = str(random.randint(1,59)).zfill(2)
		second = str(random.randint(1,50)).zfill(2)
		return day + " " + month + " " + year + " " + hour + ":" + minute + ":" + second

	def getStageEntryPoint():
		low = 300000
		high = 800000
		return str(random.randint(low,high))

	def getStageImageSizex86():
		low = 512001
		high = 576000
		return str(random.randint(low,high))

	def getStageImageSizex64():
		low = 512001
		high = 576000
		return str(random.randint(low,high))

	def getStageRichHeader():
		DanS = "\\x" + "\\x".join(["44","61","61","53"])
		DansS_second = "\\x" + "\\x".join(["00","00","00","00"])
		offset08 = "\\x" + "\\x".join(["00","00","00","00"])
		offset08_second = "\\x" + "\\x".join(["00","00","00","00"])
		content = format.getRandomByteArray(72) # 72 bytes
		Rich = "\\x" + "\\x".join(["52","69","63","68"])
		End1 = "\\x" + "\\x".join(["7a","f9","90","26"])
		End2 = "\\x" + "\\x".join(["00","00","00","00"])
		End3 = "\\x" + "\\x".join(["00","00","00","00"])
		End4 = "\\x" + "\\x".join(["00","00","00","00"])
		rich_header = str(DanS) + DansS_second + offset08 + offset08_second + content + Rich + End1 + End2 + End3 + End4
		return rich_header

	def getRandomObject():
		return random.choice(objects)

	def getNops():
		nops = [
			['90'],                                        # nop
			['50','58'],                                   # push eax; pop eax
			['66','90'],                                   # 2 bytes, 0x66; NOP *
			['0f','1f','00'],                              # 3 bytes, NOP DWORD ptr [EAX]
			['0f','1f','40','00'],                         # 4 bytes, NOP DWORD ptr [EAX + 00H]
			['0f','1f','44','00','00'],                    # 5 bytes, 66 NOP DWORD ptr [EAX + EAX*1 + 00H
			['66','0f','1f','44','00','00'],               # 6 bytes, NOP DWORD ptr [EAX + EAX*1 + 00H
			['0f','1f','80','00','00','00','00'],          # 7 bytes, NOP DWORD ptr [EAX + EAX*1 + 00000000H
			['0f','1f','84','00','00','00','00','00'],     # 8 bytes, NOP DWORD ptr [EAX + EAX*1 + 00000000H
			['66','0f','1f','84','00','00','00','00','00'] # 9 bytes, 66 NOP DWORD ptr [EAX + EAX*1 00000000H
		]
		length = random.randint(5,20)
		nopsled = ""
		for i in range(length):
			nopsled += "\\x" + "\\x".join(random.choice(nops))
		return(nopsled)

	def getHttpClientMetadataCookie():
		cookie_prefixes = [
			"_" + format.getRandomString(2) + "id",
			'SESSIONID_' + format.getRandomAlphanum(random.randint(8,32)),
			'secure_id_' + format.getRandomAlphanum(random.randint(8,32)),
			'auth_token' + format.getRandomAlphanum(4),
			'affiliate_id_' + format.getRandomAlphanum(16),
			format.getRandomAlphanum(random.randint(2,4)) +"_" + format.getRandomAlphanum(32)
			]
		cookie = random.choice(cookie_prefixes) + "="
		return cookie

	def getHttpMetadataTransform():
		transformations = ['base64url','netbios','netbiosu']
		return random.choice(transformations)

	def getHttpPostClientidParameter():
		return "_" + format.getRandomString(8)

	def allocatorSettings(method):
		rwx = "false"
		if (method == "HeapAlloc"):
			rwx = "true"
		allocator_settings = """set allocator      "{0}";
    set userwx         "{1}";""".format(method,rwx)
		return allocator_settings
