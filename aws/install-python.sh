# dependencies
sudo yum update
sudo yum install gcc bzip2-devel openssl-devel libffi-devel zlib-devel libssl-dev openssl -y 

# Python 3.7
sudo yum install python3.7

# Python 3.8
wget https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz
tar xzvf Python-3.8.1.tgz
cd Python-3.8.1
if [[ $? ]]; then
  ./configure
  sudo make altinstall
  cd ~/environment
  rm Python-3.8.1.tgz
fi

# Python 3.9
wget https://www.python.org/ftp/python/3.9.9/Python-3.9.9.tgz
tar xvf Python-3.9.9.tgz
cd Python-3.9.9/
if [[ $? ]]; then
  ./configure --enable-optimizations
  sudo make altinstall
  cd ~/environment
  rm Python-3.9.9.tgz
fi

# different dependencies required for 3.10 and 3.11
sudo yum remove openssl-devel
sudo yum groupinstall "Development Tools"
sudo yum -y install devel libffi-devel openssl11 openssl11-devel

# Python 3.10
# https://www.gcptutorials.com/post/python-3.10-installation-on-amazon-linux-2
wget https://www.python.org/ftp/python/3.10.8/Python-3.10.8.tgz
tar xzf Python-3.10.8.tgz
cd Python-3.10.8
if [[ $? ]]; then
  #sudo ./configure --with-system-ffi --with-computed-gotos --enable-loadable-sqlite-extensions --with-openssl=/usr/bin/openssl
  sudo ./configure --enable-optimizations
  # sudo make -j ${nproc}
  sudo make
  sudo make altinstall 
  cd ~/environment
  rm Python-3.10.8.tgz
fi

# Python 3.11
wget https://www.python.org/ftp/python/3.11.7/Python-3.11.7.tgz 
tar xzf Python-3.11.7.tgz 
cd Python-3.11.7 
if [[ $? ]]; then
  sudo ./configure --enable-optimizations # --with-openssl=/usr/bin/openssl
  sudo make
  sudo make altinstall
  cd ~/environment
  rm Python-3.11.7.tgz 
fi
