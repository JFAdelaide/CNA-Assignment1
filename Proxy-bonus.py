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
    
    # Check if the cached file exists
    if os.path.isfile(cacheLocation):
      # Check expiration only if metadata exists
      if os.path.isfile(cacheMetaLocation):
        with open(cacheMetaLocation, 'r') as metaFile:
          expiration_time = float(metaFile.read().strip())
        current_time = time.time()
        if current_time >= expiration_time:
          print ('Cache expired at ' + time.ctime(expiration_time) + ', fetching new copy')
          raise FileNotFoundError  # Expired, fetch from origin
      
      # Read full response (headers + body) as bytes
      with open(cacheLocation, "rb") as cacheFile:
        fullResponse = cacheFile.read()
      print ('Cache hit! Loading from cache file: ' + cacheLocation)
      clientSocket.sendall(fullResponse)
      print ('Sent full response to client')
    else:
      raise FileNotFoundError  # Cache miss

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
      expires = None

      # Parse Cache-Control: max-age if present
      for line in headers.split('\r\n'):
          if line.lower().startswith('cache-control:'):
              cache_control = line.split(':', 1)[1].strip()
              match = re.search(r'max-age=(\d+)', cache_control, re.IGNORECASE)
              if match:
                  max_age = int(match.group(1))
          elif line.lower().startswith('expires:'):
              expires_str = line.split(':', 1)[1].strip()
              try:
                  expires = time.mktime(time.strptime(expires_str, '%a, %d %b %Y %H:%M:%S GMT'))
              except ValueError:
                  print('Invalid Expires header format, ignoring')
                  expires = None

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
        if expires is not None:
          expiration_time = expires
          with open(cacheMetaLocation, 'w') as metaFile:
            metaFile.write(str(expiration_time))
          print ('Cached with expiration at ' + time.ctime(expiration_time))
        elif max_age is not None:
          expiration_time = time.time() + max_age
          with open(cacheMetaLocation, 'w') as metaFile:
            metaFile.write(str(expiration_time))
          print ('Cached with expiration at ' + time.ctime(expiration_time))

      # Pre-fetching for HTML resources
      if 'text/html' in headers.lower():
          print('Detected HTML, attempting pre-fetch')
          body_str = body.decode('utf-8', errors='ignore')
          links = re.findall(r'(?:href|src)=["\'](.*?)["\']', body_str)
          print(f'Found {len(links)} links: {links}')
          for link in links:
              if link and not link.startswith(('http://', 'https://', '//', '#')):
                  resource_path = link if link.startswith('/') else '/' + link
                  prefetch_location = './' + hostname + resource_path
                  if prefetch_location.endswith('/'):
                      prefetch_location += 'default'
                  if not os.path.isfile(prefetch_location):
                      try:
                          print(f'Fetching {resource_path}')
                          prefetch_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                          prefetch_socket.settimeout(5)  # 5-second timeout
                          prefetch_socket.connect((socket.gethostbyname(hostname), 80))
                          prefetch_socket.sendall(f"GET {resource_path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
                          prefetch_response = b""
                          while True:
                              data = prefetch_socket.recv(BUFFER_SIZE)
                              if not data:
                                  break
                              prefetch_response += data
                          prefetch_socket.close()
                          os.makedirs(os.path.dirname(prefetch_location), exist_ok=True)
                          with open(prefetch_location, 'wb') as f:
                              f.write(prefetch_response)
                          print(f'Prefetched: {prefetch_location}')
                      except Exception as e:
                          print(f'Failed to prefetch {resource_path}: {e}')
                  else:
                      print(f'Skipped prefetching {resource_path}: already cached')

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