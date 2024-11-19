import cv2


class VideoStream:
    def __init__(self, filename):
        self.videoCapture = cv2.VideoCapture(filename)
        if not self.videoCapture.isOpened():
            raise IOError("Could not Open")
        self.frameNum = 0
        
    def nextFrame(self):
        """Get next frame."""
        ret,frame = self.videoCapture.read()
        if ret:
            self.frameNum += 1
            _, encoded_frame = cv2.imencode('.jpg',frame)
            return encoded_frame.tobytes()
        else:
            return None
        
    def frameNbr(self):
        """Get frame number."""
        return self.frameNum
    
    
    def release(self):
        self.videoCapture.release()
    