import sys, socket
import cv2
import numpy as np
from random import randint
import traceback, threading

from RtpPacket import RtpPacket

class Servidor:    

	clientInfo = {}

	def sendRtp(self):
		"""Send RTP packets over UDP."""
		while True:
			self.clientInfo['event'].wait(0.05)
			
			# Stop sending if request is PAUSE or TEARDOWN
			if self.clientInfo['event'].is_set():
				break
				
			ret, data = self.clientInfo['videoStream'].read()
			if ret:
				frameNumber = int(self.clientInfo['videoStream'].get(cv2.CAP_PROP_POS_FRAMES))
				try:
					address = self.clientInfo['rtpAddr']
					port = int(self.clientInfo['rtpPort'])
					packet = self.makeRtp(data, frameNumber)
					self.clientInfo['rtpSocket'].sendto(packet, (address, port))
				except:
					print("Connection Error")
					print('-'*60)
					traceback.print_exc(file=sys.stdout)
					print('-'*60)
		# Close the RTP socket
		self.clientInfo['rtpSocket'].close()
		print("All done!")

	def makeRtp(self, payload, frameNbr):
		"""RTP-packetize the video data."""
		version = 2
		padding = 0
		extension = 0
		cc = 0
		marker = 0
		pt = 26  # MJPEG type
		seqnum = frameNbr
		ssrc = 0

		# Encode the frame to JPEG
		_, encoded_image = cv2.imencode('.jpg', payload)
		rtpPacket = RtpPacket()
		
		rtpPacket.encode(version, padding, extension, cc, seqnum, marker, pt, ssrc, encoded_image.tobytes())
		print("Encoding RTP Packet: " + str(seqnum))
		
		return rtpPacket.getPacket()

	def main(self):
		try:
			# Get the media file name
			filename = sys.argv[1]
			print("Using provided video file ->  " + filename)
		except:
			print("[Usage: Servidor.py <videofile>]\n")
			filename = "videos/movie.Mjpeg"
			print("Using default video file ->  " + filename)

		# videoStream
		self.clientInfo['videoStream'] = cv2.VideoCapture(filename)
		if not self.clientInfo['videoStream'].isOpened():
			print("Error opening video stream or file")
			sys.exit(1)

		# socket
		self.clientInfo['rtpPort'] = 25000
		self.clientInfo['rtpAddr'] = socket.gethostbyname('127.0.0.1')
		print("Sending to Addr:" + self.clientInfo['rtpAddr'] + ":" + str(self.clientInfo['rtpPort']))
		# Create a new socket for RTP/UDP
		self.clientInfo["rtpSocket"] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.clientInfo['event'] = threading.Event()
		self.clientInfo['worker'] = threading.Thread(target=self.sendRtp)
		self.clientInfo['worker'].start()

if __name__ == "__main__":
	(Servidor()).main()

