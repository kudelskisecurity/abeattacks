# syntax=docker/dockerfile:1
FROM ubuntu:18.04 

RUN apt update -y
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime
RUN apt-get install -y tzdata
RUN dpkg-reconfigure --frontend noninteractive tzdata
RUN apt-get --assume-yes install software-properties-common

RUN add-apt-repository ppa:deadsnakes/ppa -y
RUN apt update -y
RUN apt install python3.7 python3.7-dev -y
RUN apt install python3-virtualenv -y
RUN apt install build-essential sudo python3-dev wget flex bison python3-pip libssl-dev libgmp10 libgmp-dev git openssl -y
RUN rm -f /usr/bin/python && ln -s /usr/bin/python3.7 /usr/bin/python
RUN rm -f /usr/bin/python3 && ln -s /usr/bin/python3.7 /usr/bin/python3
WORKDIR /root
RUN git clone https://github.com/JHUISI/charm
WORKDIR /root/charm
RUN git checkout 55d82436d5da1a830fb16d6536700d9d61c0149d
RUN ./configure.sh
RUN python3.7 -m pip install -r requirements.txt
WORKDIR /root/charm/deps/pbc
RUN make
RUN ldconfig
WORKDIR /root/charm/
RUN make 
RUN make install 
RUN ldconfig
WORKDIR /abe
WORKDIR /abe/backend
COPY backend/ .
WORKDIR /abe/backend/attacks/jupyter/
RUN apt install vim -y
RUN python3.7 -m pip install cffi==1.14.6 abeattacks jupyter
# Add Tini. Tini operates as a process subreaper for jupyter. This prevents kernel crashes.
ENV TINI_VERSION v0.6.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /usr/bin/tini
RUN chmod +x /usr/bin/tini
ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["jupyter", "notebook", "--port=8888", "--no-browser", "--ip=0.0.0.0", "--allow-root"]


#CMD ["/bin/bash"]








