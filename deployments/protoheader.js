
const Proto = module.exports

Proto.PROTO_FLAG = Buffer.from('sensible')

Proto.PROTO_FLAG_LEN = Proto.PROTO_FLAG.length
Proto.TYPE_LEN = 4
Proto.VERSION_LEN = 4
Proto.TYPE_OFFSET = Proto.PROTO_FLAG_LEN + Proto.TYPE_LEN
Proto.VERSION_OFFSET = Proto.TYPE_OFFSET + Proto.VERSION_LEN
Proto.HEADER_LEN = Proto.VERSION_OFFSET

Proto.getHeaderLen = function () {
  return Proto.HEADER_LEN
}

Proto.getFlag = function (script) {
  return script.subarray(script.length - Proto.PROTO_FLAG_LEN, script.length)
}

Proto.getProtoType = function (script) {
  return script.readUIntLE(script.length - Proto.TYPE_OFFSET, Proto.TYPE_LEN)
}

Proto.getProtoVersion = function (script) {
  return script.readUIntLE(script.length - Proto.VERSION_OFFSET, Proto.VERSION_LEN)
}

Proto.HasProtoFlag = function (script) {
  const flag = Proto.getFlag(script)
  if (flag.compare(Proto.PROTO_FLAG) === 0) {
    return true
  }
  return false
}