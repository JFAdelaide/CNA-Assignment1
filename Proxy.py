# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
import time

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~
  serverSocket.bind((proxyHost, proxyPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket.listen(5)
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, address = serverSocket.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'
    
    # Add metadata file for expiration tracking
    cacheMetaLocation = cacheLocation + '.meta'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Check wether the file is currently in the cache
    cacheFile = open(cacheLocation, "r")
    cacheData = cacheFile.readlines()

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    clientSocket.sendall(''.join(cacheData).encode('utf-8'))
    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + ''.join(cacheData))
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerSocket.connect((address, 80))
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      originServerRequest = f"{method} {resource} {version}"
      originServerRequestHeader = f"Host: {hostname}"
      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      response = b""
      headers_received = False
      content_length = None
      bytes_received = 0

      while True:
        data = originServerSocket.recv(BUFFER_SIZE)
        if not data:  # Connection closed by server
          break
        response += data

        # Parse headers if not yet received
        if not headers_received and b'\r\n\r\n' in response:
          headers_end = response.index(b'\r\n\r\n') + 4
          headers = response[:headers_end].decode('utf-8', errors='ignore')
          headers_received = True

          # Look for Content-Length
          for line in headers.split('\r\n'):
            if line.lower().startswith('content-length:'):
              content_length = int(line.split(':')[1].strip())
              break

        # If we have Content-Length and headers, check if we've received all data
        if headers_received and content_length is not None:
          bytes_received = len(response) - headers_end
          if bytes_received >= content_length:
            break

      # If no Content-Length and headers received, assume response is complete
      if headers_received and content_length is None:
        break
      # ~~~~ END CODE INSERT ~~~~

      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      clientSocket.sendall(response)

      # Handle Status Code and Cache-Control
      # Split response for header modification
      headers_end = response.index(b'\r\n\r\n') + 4
      headers = response[:headers_end].decode('utf-8', errors='ignore')
      body = response[headers_end:]

      # Extract status code from headers
      status_line = headers.split('\r\n')[0]
      status_code = status_line.split()[1]
      
      should_cache = True
      max_age = None

      # Handle 301 - Permanent Redirect (Cached for 24 hours)
      if status_code == '301':
        max_age = 86400
      
      # Handle 302 - Temporary Redirect (Cached for 1 hour)
      if status_code == '302':
        max_age = 3600
      
      # Handle 404 - Not Found (Not Cached)
      if status_code == '404':
        should_cache = False

      # Add Cache-Control header if max_age is set
      if max_age is not None:
          cache_control_line = f'Cache-Control: max-age={max_age}\r\n'
          if 'Cache-Control:' not in headers:
              headers = headers.rstrip('\r\n') + '\r\n' + cache_control_line
          else:
              headers = re.sub(r'Cache-Control:.*\r\n', cache_control_line, headers)
          response = headers.encode('utf-8') + body
      # ~~~~ END CODE INSERT ~~~~

      if should_cache:
        # Create a new file in the cache for the requested file.
        cacheDir, file = os.path.split(cacheLocation)
        print ('cached directory ' + cacheDir)
        if not os.path.exists(cacheDir):
          os.makedirs(cacheDir)
        cacheFile = open(cacheLocation, 'wb')

        # Save origin server response in the cache file
        # ~~~~ INSERT CODE ~~~~
        cacheFile.write(response)
        # ~~~~ END CODE INSERT ~~~~
        cacheFile.close()
        print ('cache file closed')

        # Save expiration time to metadata file
        if max_age is not None:
            expiration_time = time.time() + max_age
            with open(cacheMetaLocation, 'w') as metaFile:
                metaFile.write(str(expiration_time))
            print ('Cached with expiration at ' + time.ctime(expiration_time))

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')