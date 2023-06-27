# SPDX-License-Identifier: ISC

defmodule TorCertRsaEd25519Test do
  use ExUnit.Case
  doctest TorCert.RsaEd25519

  test "fetches a TorCert.RsaEd25519" do
    data =
      <<0::8*32>> <>
        <<0::32>> <>
        <<32>> <>
        <<0::8*64>>

    {cert, data} = TorCert.RsaEd25519.fetch(data)

    assert cert == %TorCert.RsaEd25519{
             ed25519_key: <<0::32*8>>,
             expiration_date: DateTime.from_unix!(0),
             signature: <<0::32*8>>
           }

    assert data == <<0::32*8>>
  end

  test "encodes a TorCert.RsaEd25519" do
    cert = %TorCert.RsaEd25519{
      ed25519_key: <<0::32*8>>,
      expiration_date: DateTime.from_unix!(0),
      signature: <<0::32*8>>
    }

    assert TorCert.RsaEd25519.encode(cert) == <<0::8*32>> <> <<0::32>> <> <<32>> <> <<0::8*32>>
  end

  test "verify a TorCert.RsaEd25519" do
    raw =
      <<194, 4, 162, 205, 242, 49, 217, 184, 187, 127, 147, 15, 211, 173, 83, 179, 26, 111, 116,
        63, 71, 28, 173, 15, 33, 128, 137, 199, 170, 24, 162, 214, 0, 7, 48, 155, 128, 9, 96, 80,
        227, 196, 80, 231, 98, 239, 52, 34, 23, 69, 78, 249, 215, 190, 154, 91, 209, 163, 7, 141,
        180, 49, 228, 10, 248, 97, 67, 10, 38, 88, 48, 83, 214, 35, 166, 199, 224, 160, 235, 115,
        117, 119, 85, 44, 72, 59, 130, 165, 69, 225, 70, 93, 245, 18, 29, 240, 48, 152, 196, 34,
        78, 180, 108, 177, 39, 225, 195, 150, 10, 75, 152, 242, 52, 5, 127, 228, 92, 134, 181,
        183, 201, 37, 142, 92, 34, 11, 253, 76, 48, 242, 47, 107, 206, 183, 4, 54, 169, 126, 161,
        221, 240, 140, 1, 167, 196, 28, 50, 185, 145, 227, 113, 232, 88, 1, 70, 72, 117, 232, 224,
        51, 40, 51, 130, 108, 58>>

    {cert, _} = TorCert.RsaEd25519.fetch(raw)

    key = "-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOZmLLx5QsbIZcLtAFvqXeCUIhpyOxHnRvwYTFIihVRMx2DuZWT8Stds
AQsOPFZZ7e5pH1xM/KR8L3nUtrZyQ9JefGorZYrE6dzf2p4mTiiG2xDo/6rWb0Q+
/vJilOmN9d5yKY3bTToiw+/QV86O+a8WI0kyCRDQAjH33EPmXwfpAgMBAAE=
-----END RSA PUBLIC KEY-----"
    key = :public_key.pem_entry_decode(hd(:public_key.pem_decode(key)))

    assert TorCert.RsaEd25519.is_valid?(cert, key, ~U[2023-10-03 02:00:00Z])
  end
end
