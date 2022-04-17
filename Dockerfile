FROM golang:alpine
WORKDIR /go/src/github.com/polylan/broadcast_proxy
COPY main.go ./
RUN apk add --no-cache libpcap-dev libcap-dev git gcc libc-dev
RUN go get github.com/google/gopacket/layers && \
    go get github.com/google/gopacket/pcap && \
    go build --ldflags '-linkmode external -extldflags "-static -s -w"' -v ./

FROM scratch 
WORKDIR /
COPY --from=0 /go/src/github.com/polylan/broadcast_proxy/broadcast_proxy ./
COPY  games.csv ./
ENTRYPOINT ["/broadcast_proxy"]
