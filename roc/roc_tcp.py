#!/usr/bin/env python
# -*- coding: utf_8 -*-


"""
 TestKit: Implementation of Fisher ROC protocol in python
 This is distributed under GNU LGPL license, see license.txt
"""


import socket
import select
import struct
import datetime

import crc


#*************************************************************************************************************
# 
#*************************************************************************************************************
class TimeoutError(Exception):
	def __init__(self, sError):
		self.error = sError
	def __str__(self):
		return repr(self.error)


#*************************************************************************************************************
# 
#*************************************************************************************************************
class OpcodeError(Exception):
	def __init__(self, iOpcode, iErrorCode, aAdd):
		self.opcode = iOpcode
		self.errorcode = iErrorCode
		self.address = aAdd
		self.data = []
		
	def __str__(self):
		if self.opcode == 180:
			try:
				for aTlp in self.address:
					for i in aTlp:
						self.data.append(i)
				aTlp = []
				for i in self.data[self.errorcode-7:self.errorcode-4]:
					aTlp.append(str(i))
				self.errorcode = " ".join(aTlp)
			except Exception, ex:
				pass
		return "Opcode Error: Opcode:%s Device Parameter:%s"%(repr(self.opcode), repr(self.errorcode))


#*************************************************************************************************************
# TCP Master Object
#*************************************************************************************************************
class TcpMaster(object):
	
	def __init__(self, server="127.0.0.1", port=4000, host_group=3, host_address=1, timeout_in_sec=5.0):
		self.timeout_in_sec = timeout_in_sec
		self._server = server
		self._port = port
		self._sock = None
		self._host_group = host_group
		self._host_address = host_address
		self.access = False
	
	#=============================================================================================================
	# Connect to slave device
	#=============================================================================================================
	def _do_open(self):
		if self._sock:
			self._sock.close()
		self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.set_timeout(self.timeout_in_sec)
		self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self._sock.connect((self._server, self._port))

	
	#=============================================================================================================
	# Close Connection
	#=============================================================================================================
	def _do_close(self):
		"""Close the connection with the Slave"""
		if self._sock:
			self._sock.close()
			self._sock = None
		return True
	
	
	#=============================================================================================================
	# Send Request to the slave
	#=============================================================================================================
	def _send(self, request):
		try:
			flush_socket(self._sock, 3)
		except Exception as msg:
			#if we can't flush the socket successfully: a disconnection may happened
			#try to reconnect
			self._do_open()
		print  "TX:"+" ".join("{:02x}".format(ord(c)) for c in request)
		self._sock.send(request)
	
	
	#=============================================================================================================
	# Recieve data from slave
	#=============================================================================================================
	def _recv(self, expected_length=-1):
		response = []
		length = 255
		while len(response) < length:
			rcv_byte = self._sock.recv(1)
			if rcv_byte:
				response.append(struct.unpack('B',rcv_byte)[0])
				#response += rcv_byte
				if len(response) == 6:
					to_be_recv_length = struct.unpack('B',rcv_byte)[0]
					length = to_be_recv_length + 6 + 2
				
			else:
				break
		
		print "RX:"+" ".join(["{:02x}".format(i) for i in response])
		return response
	
	
	
	#=============================================================================================================
	# Set Timeout
	#=============================================================================================================
	def set_timeout(self, timeout_in_sec):
		if self._sock:
			self._sock.setblocking(timeout_in_sec > 0)
			if timeout_in_sec:
				self._sock.settimeout(timeout_in_sec)
	
    
    
    #=============================================================================================================
	# OPCODE 8 SET REAL TIME CLOCK
	#=============================================================================================================
	def opcode8(self, address, group, seconds, minutes, hours, day, month, year,expected_length=-1):
		data = [address, group, self._host_address, self._host_group, 8, 6, seconds, minutes, hours, day, month, year]
		request = ""
		for i in data:
			request += struct.pack('B',i)
		for i in crc.crc16(request):
			request += struct.pack('B',i)
		self._send(request)
		data = self._recv()
		responsecrc = data[-2:]
		data = data[:-2]
		response = ""
		for i in data:
			response += struct.pack('B',i)
		
		if not(crc.crc16(response) == responsecrc):
			raise RuntimeError('CRC Error')
		
		if not(data[0] == self._host_address) or not(data[1] == self._host_group):
			raise RuntimeError('Incorrect Host Address in Response')
		
		if not(data[2] == address) or not(data[3] == group):
			raise RuntimeError('Incorrect Device Address in Response')
		
		if not(data[4] == 8) and (data[4] != 255):
			raise RuntimeError('Incorrect OPCode in Response')
		
		if (data[4] == 255):
			raise OpcodeError(data[7], data[8],[])

		if (data[5] == 0):
			return True
		
		else:
			return False

	#=============================================================================================================
	# OPCODE 17 LOGIN
	#=============================================================================================================
	def opcode17(self, address, group, expected_length=-1):
		data = [address, group, self._host_address, self._host_group, 17, 5,76,79,73,03,232]
		request = ""
		for i in data:
			request += struct.pack('B',i)
		for i in crc.crc16(request):
			request += struct.pack('B',i)
		self._send(request)
		data = self._recv()
		responsecrc = data[-2:]
		data = data[:-2]
		response = ""
		for i in data:
			response += struct.pack('B',i)
		
		if not(crc.crc16(response) == responsecrc):
			raise RuntimeError('CRC Error')
		
		if not(data[0] == self._host_address) or not(data[1] == self._host_group):
			raise RuntimeError('Incorrect Host Address in Response')
		
		if not(data[2] == address) or not(data[3] == group):
			raise RuntimeError('Incorrect Device Address in Response')
		
		if not(data[4] == 17) and (data[4] != 255):
			raise RuntimeError('Incorrect OPCode in Response')
		
		if (data[4] == 255):
			raise OpcodeError(data[7], data[8],[])

		return data

    #=============================================================================================================
	# OPCODE 120 POINTER
	#=============================================================================================================
	def opcode120(self, address, group, expected_length=-1):
		data = [address, group, self._host_address, self._host_group, 120,0]
		request = ""
		for i in data:
			request += struct.pack('B',i)
		for i in crc.crc16(request):
			request += struct.pack('B',i)
		self._send(request)
		data = self._recv()
		responsecrc = data[-2:]
		data = data[:-2]
		response = ""
		for i in data:
			response += struct.pack('B',i)
		
		if not(crc.crc16(response) == responsecrc):
			raise RuntimeError('CRC Error')
		
		if not(data[0] == self._host_address) or not(data[1] == self._host_group):
			raise RuntimeError('Incorrect Host Address in Response')
		
		if not(data[2] == address) or not(data[3] == group):
			raise RuntimeError('Incorrect Device Address in Response')
		
		if not(data[4] == 120) and (data[4] != 255):
			raise RuntimeError('Incorrect OPCode in Response')
		if (data[4] == 255):
			raise OpcodeError(data[7], data[8],[])
		dData = {}
		
		#Alarm Pointer
		value = ""
		value += struct.pack('B',data[6])
		value += struct.pack('B',data[7])
		dData['alarm_pointer'] = struct.unpack('H',value)[0]
		
		#Event Pointer
		value = ""
		value += struct.pack('B',data[8])
		value += struct.pack('B',data[9])
		dData['event_pointer'] = struct.unpack('H',value)[0]
		
		#Hourly Index
		value = ""
		value += struct.pack('B',data[10])
		value += struct.pack('B',data[11])
		dData['hourly_index'] = struct.unpack('H',value)[0]
		
		#Extended Index
		value = ""
		value += struct.pack('B',data[12])
		value += struct.pack('B',data[13])
		dData['extended_index'] = struct.unpack('H',value)[0]
		
		#Extended Number
		value = ""
		value += struct.pack('B',data[14])
		value += struct.pack('B',data[15])
		dData['number_extended'] = struct.unpack('H',value)[0]
		
		#Daily Index
		value = ""
		value += struct.pack('B',data[18])
		value += struct.pack('B',data[19])
		dData['daily_index'] = struct.unpack('H',value)[0]
		
		#Max Number Of Alarms (Normally 240)
		value = ""
		value += struct.pack('B',data[22])
		value += struct.pack('B',data[23])
		dData['max_alarms'] = struct.unpack('H',value)[0]
		
		#Max Number Of Events (Normally 240)
		value = ""
		value += struct.pack('B',data[24])
		value += struct.pack('B',data[25])
		dData['max_events'] = struct.unpack('H',value)[0]
		
		#Number of Days of Daily History Logs
		dData['days_daily'] = data[26]
		
		#Number of Days of Hourly History Logs
		dData['days_hourly'] = data[27]
		
		#Number of Minutes of Minute History Logs
		dData['minutes_minute'] = data[30]
		return dData


    #=============================================================================================================
	# OPCODE 126 MINUTE HISTORY
	#=============================================================================================================
	def opcode126(self, address, group, point, expected_length=-1):
		data = [address, group, self._host_address, self._host_group, 126, 1, point]
		clock = self.opcode180(address=address, group=group, TLP=[[12,0,5],[12,0,4],[12,0,3],[12,0,2]], data_format=['b','b','b','b'])
		iHour = clock[3]
		sDate = "20%2d-%02d-%02d"%(clock[0],clock[1],clock[2])
		request = ""
		for i in data:
			request += struct.pack('B',i)
		for i in crc.crc16(request):
			request += struct.pack('B',i)
		self._send(request)
		data = self._recv()
		responsecrc = data[-2:]
		data = data[:-2]
		response = ""
		for i in data:
			response += struct.pack('B',i)
		
		if not(crc.crc16(response) == responsecrc):
			raise RuntimeError('CRC Error')
		if not(data[0] == self._host_address) or not(data[1] == self._host_group):
			raise RuntimeError('Incorrect Host Address in Response')
		
		if not(data[2] == address) or not(data[3] == group):
			raise RuntimeError('Incorrect Device Address in Response')
		
		if not(data[4] == 126) and (data[4] != 255):
			raise RuntimeError('Incorrect OPCode in Response')
		if (data[4] == 255):
			raise OpcodeError(data[7], data[8],[])
		
		if not(data[6] == point):
			raise RuntimeError('Incorrect Pointer in Response')
		
		iMin = data[7]
		hist = data[8:]
		iBit = 0
		aHist = []
		for i in range(60):
		    value = ''
		    value += struct.pack('B',hist[iBit])
		    value += struct.pack('B',hist[iBit + 1])
		    value += struct.pack('B',hist[iBit + 2])
		    value += struct.pack('B',hist[iBit + 3])
		    aValue = struct.unpack('f',value)
		    iBit += 4
		    date_time = datetime.datetime(clock[0]+2000,clock[1],clock[2],iHour,i, 00)
		    if i >= iMin:
		    	date_time = date_time - datetime.timedelta(hours=1)
		    sTime = date_time.strftime('%Y-%m-%d %H:%M:%S')
		    aHist.append({'date_time':sTime, 'value': aValue[0]})
		return aHist

    
	#=============================================================================================================
	# OPCODE 128 Read Daily History
	#=============================================================================================================
	def opcode128(self, address, group, point, day, month, expected_length=-1):
		data = [address, group, self._host_address, self._host_group, 128, 3, point, day, month]
		request = ""
		for i in data:
			request += struct.pack('B',i)
		for i in crc.crc16(request):
			request += struct.pack('B',i)
		self._send(request)
		data = self._recv()
		responsecrc = data[-2:]
		data = data[:-2]
		response = ""
		for i in data:
			response += struct.pack('B',i)
		
		if not(crc.crc16(response) == responsecrc):
			raise RuntimeError('CRC Error')
		if not(data[0] == self._host_address) or not(data[1] == self._host_group):
			raise RuntimeError('Incorrect Host Address in Response')
		
		if not(data[2] == address) or not(data[3] == group):
			raise RuntimeError('Incorrect Device Address in Response')
		
		if not(data[4] == 128) and (data[4] != 255):
			raise RuntimeError('Incorrect OPCode in Response')
		if (data[4] == 255):
			raise OpcodeError(data[7], data[8],[])
		
		if not(data[7] == month) or not(data[8] == day):
			raise RuntimeError('Incorrect Date in Response')
		
		value = ''
		value += struct.pack('B',data[109])
		value += struct.pack('B',data[110])
		value += struct.pack('B',data[111])
		value += struct.pack('B',data[112])
		aValue = struct.unpack('f',value)
		print "Job Done Data:%s"%(",".join(map(str, aValue)))
		return aValue

		
	#=============================================================================================================
	# OPCODE 180 Read TLP
	#=============================================================================================================
	def opcode180(self, address, group, TLP, data_format=[], expected_length=-1):
		data = [address, group, self._host_address, self._host_group, 180, (len(TLP)*3)+1, len(TLP)]
		self.data_format = data_format
		length = 1
		regs = 0
		for t,l,p in TLP:
			length += 3
			regs += 1
			data.append(t)
			data.append(l)
			data.append(p)
			
		request = ""
		for i in data:
			request += struct.pack('B',i)
		for i in crc.crc16(request):
			request += struct.pack('B',i)
		
		self._send(request)
		
		data = self._recv()
		responsecrc = data[-2:]
		data = data[:-2]
		response = ""
		for i in data:
			response += struct.pack('B',i)
		
		if not(crc.crc16(response) == responsecrc):
			raise RuntimeError('CRC Error')
		if not(data[0] == self._host_address) or not(data[1] == self._host_group):
			raise RuntimeError('Incorrect Host Address in Response')
		
		if not(data[2] == address) or not(data[3] == group):
			raise RuntimeError('Incorrect Device Address in Response')
		
		if not(data[4] == 180) and (data[4] != 255):
			raise RuntimeError('Incorrect OPCode in Response')
		if (data[4] == 255):
			raise OpcodeError(data[7], data[8],TLP)
		
		tlplength = data[6]
		data = data[7:]
		value = ''
		for i in range(len(TLP)):
			t,l,p = TLP[i]
			if not(data[0] == t) or not(data[1] == l) or not(data[2] == p):
				raise RuntimeError('TLP Recieved is not TLP Requested')
			if data_format[i] in ['f','q','L','l','i']:
				value += struct.pack('B',data[3])
				value += struct.pack('B',data[4])
				value += struct.pack('B',data[5])
				value += struct.pack('B',data[6])
				data = data[7:]
			elif data_format[i] in ['h','H']:
				value += struct.pack('B',data[3])
				value += struct.pack('B',data[4])
				data = data[5:]
			elif data_format[i] in ['b','B']:
				value += struct.pack('B',data[3])
				data = data[4:]
			else:
				#MUST BE A STRING (c)
				stringlength = int(data_format[i].replace('c',''))
				dataformat = ''
				for x in range(stringlength):
					dataformat += 'c'
					value += struct.pack('B',data[3+x])
				data = data[3+stringlength:]
				data_format[i] = dataformat
		aValue = struct.unpack('=%s'%(''.join(data_format)),value)
		print "Job Done Data:%s"%(",".join(map(str, aValue)))
		return aValue
	
	
	#=============================================================================================================
	# OPCODE 181 WRITE TLP
	#=============================================================================================================
	def opcode181(self, address, group, TLP, data_format, values, expected_length=-1):
		data = [address, group, self._host_address, self._host_group, 181,0,0]
		length = 1
		regs = 0
		for i in range(len(TLP)):
			t,l,p = TLP[i]
			length += 3
			regs += 1
			data.append(t)
			data.append(l)
			data.append(p)
			if data_format[i] in ['f','q','L','l','i']:
				length += 4
				for byte in struct.pack(data_format[i], values[i]):
					data.append(struct.unpack('B',byte)[0])
			elif data_format[i] in ['h','H']:
				length += 2
				for byte in struct.pack(data_format[i], values[i]):
					data.append(struct.unpack('B',byte)[0])
			elif data_format[i] in ['b','B']:
				length += 1
				for byte in struct.pack(data_format[i], values[i]):
					data.append(struct.unpack('B',byte)[0])
			else:
				#Must be a string
				stringlength = int(data_format[i].replace('c',''))
				data_format = ''
				for x in range(stringlength):
					length += 1
					data_format += 'c'
					data.append(struct.unpack('B',values[x])[0])
				
		data[5] = length
		data[6] = regs
		
		request = ""
		for i in data:
			request += struct.pack('B',i)
		for i in crc.crc16(request):
			request += struct.pack('B',i)
		
		self._send(request)
		data = self._recv()
		responsecrc = data[-2:]
		data = data[:-2]
		
		response = ""
		for i in data:
			response += struct.pack('B',i)
			
		if not(crc.crc16(response) == responsecrc):
			raise RuntimeError('CRC Error')
		
		if not(data[0] == self._host_address) or not(data[1] == self._host_group):
			raise RuntimeError('Incorrect Host Address in Response')
		
		if not(data[2] == address) or not(data[3] == group):
			raise RuntimeError('Incorrect Device Address in Response')
		
		if not(data[4] == 181):
			raise RuntimeError('Incorrect OPCode in Response')
		
		if (data[5] == 0):
			#Good Response
			return tuple(values)
		
	
	
		


