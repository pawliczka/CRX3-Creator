import dircache
import os
import zipfile
import crx3_pb2
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
import argparse
import io

kCrxFileHeaderMagic = "Cr24"
VERSION = struct.pack("<I", 3)
kSignatureContext = 'CRX3 SignedData\00'
fileBufferLength = 4096


def rm_trailing_slash(d):
  return d[:-1] if d.endswith(os.path.sep) else d


def create_publickey(private_key):
  public_key = private_key.public_key();
  data = public_key.public_bytes(encoding=serialization.Encoding.DER,
                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
  return data


def create_privatekey(path, crxd):
  if os.path.exists(path):
    with open(path, "rb") as pf:
      key = serialization.load_pem_private_key(
        pf.read(),
        password=None,
        backend=default_backend())
      pem = pf.read()
      return pem, key
  pemfile = "%s.pem" % crxd
  with open(pemfile, "wb") as pf:
    private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend())
    pem = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption())
    pf.write(pem)
    return pem, private_key


def package(basedir, private_key, output, files=None):
  if not os.path.isdir(basedir):
    raise IOError("Non-existant directory <%s>" % basedir)
  crxd = rm_trailing_slash(basedir)
  try:
    zipdata = zipdir(crxd, inject=files)
  except IOError as e:
    raise e

  pem, private_key = create_privatekey(private_key, crxd)
  public_key = create_publickey(private_key)

  signed_header_data_str = create_signed_header_data_str(public_key)

  signed = sign(signed_header_data_str, zipdata, private_key)
  header_str = create_header_str(public_key, signed, signed_header_data_str)

  save_crx_file(header_str, zipdata, output, crxd)


def sign(signed_header_data_str, zipped, private_key):
  signed_header_size_octets = struct.pack("<I", len(signed_header_data_str))

  chosen_hash = hashes.SHA256()
  hasher = hashes.Hash(chosen_hash, default_backend())
  hasher.update(kSignatureContext)
  hasher.update(signed_header_size_octets)
  hasher.update(signed_header_data_str)

  for i in range(0, len(zipped), fileBufferLength):
    if (i + fileBufferLength <= len(zipped)):
      hasher.update(zipped[i: i + fileBufferLength])
    else:
      hasher.update(zipped[i: len(zipped)])

  digest = hasher.finalize()

  return private_key.sign(
    digest,
    padding.PKCS1v15(),
    utils.Prehashed(chosen_hash)
  )


def zipdir(directory, inject=None):
  zip_memory = io.BytesIO()
  with zipfile.ZipFile(zip_memory, "w", zipfile.ZIP_DEFLATED) as zf:
    def _rec_zip(path, parent="", inject=None):
      if inject:
        for fname, fdata in inject.items():
          fpath = '%s/%s' % (directory, fname)
          zf.writestr(fname, fdata)

      for d in dircache.listdir(path):
        child = os.path.join(path, d)
        name = "%s/%s" % (parent, d)
        if os.path.isfile(child):
          zf.write(child, name)
        if os.path.isdir(child):
          _rec_zip(child, name)

    _rec_zip(directory, "", inject=inject)
    zf.close()
    zipdata = zip_memory.getvalue()
    return zipdata
  raise IOError("Failed to create zip")


def argparser():
  parser = argparse.ArgumentParser(description="crx3 creator")
  parser.add_argument("src", type=str, default='',
                      help="Source directory containing unpacked chrome ext")
  parser.add_argument("-o", "--output", type=str, default='',
                      help="File location for packed .crx")
  parser.add_argument("-pem", "--private-key", type=str, default='',
                      help="Private key location if no private key script will generate and save private key")
  return parser


def cli():
  parser = argparser()
  args = parser.parse_args()
  package(args.src, args.private_key, args.output)


def get_crx_id(public_key):
  digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
  digest.update(public_key)
  hased = digest.finalize()
  return hased[0:16]


def create_signed_header_data_str(public_key):
  signed_header_data = crx3_pb2.SignedData()
  signed_header_data.crx_id = get_crx_id(public_key)
  return signed_header_data.SerializeToString()


def create_header_str(public_key, signed, signed_header_data_str):
  header = crx3_pb2.CrxFileHeader()
  proof = header.sha256_with_rsa.add()
  proof.public_key = public_key
  proof.signature = signed
  header.signed_header_data = signed_header_data_str
  return header.SerializeToString()


def save_crx_file(header_str, zipped, path, crdx):
  header_size_octets = struct.pack("<I", len(header_str))

  fileLocation = path if path else '%s.crx' % crdx
  with open(fileLocation, 'wb') as crx:
    data = [kCrxFileHeaderMagic, VERSION, header_size_octets, header_str,
            zipped]
    for d in data:
      crx.write(d)


if __name__ == "__main__":
  cli()
