-record(multipart_body, {
    chunk :: bitstring(),
    done :: boolean(),
    remaining :: bitstring()
}).
