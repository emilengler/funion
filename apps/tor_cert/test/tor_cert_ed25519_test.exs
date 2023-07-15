# SPDX-License-Identifier: ISC

defmodule TorCertEd25519Test do
  use ExUnit.Case
  doctest TorCert.Ed25519

  test "decodes a TorCert.Ed25519" do
    extensions = <<32::16, 0x04, 0, 0::8*32, 32::16, 0x04, 1, 0::8*32>>
    data = <<1, 0x04, 0::32, 1, 0::8*32, 2>> <> extensions <> <<0::128*8>>

    cert = TorCert.Ed25519.decode(data)

    assert cert == %TorCert.Ed25519{
             cert_type: :ed25519_signing_id,
             expiration_date: DateTime.from_unix!(0),
             cert_key_type: :ed25519,
             certified_key: <<0::8*32>>,
             extensions: [
               %TorCert.Ed25519.Extension{
                 type: :signed_with_ed25519_key,
                 flags: nil,
                 data: <<0::8*32>>
               },
               %TorCert.Ed25519.Extension{
                 type: :signed_with_ed25519_key,
                 flags: :affects_validation,
                 data: <<0::8*32>>
               }
             ],
             signature: <<0::8*64>>
           }
  end

  test "encodes a TorCert.Ed25519" do
    cert = %TorCert.Ed25519{
      cert_type: :ed25519_signing_id,
      expiration_date: DateTime.from_unix!(0),
      cert_key_type: :ed25519,
      certified_key: <<0::8*32>>,
      extensions: [
        %TorCert.Ed25519.Extension{
          type: :signed_with_ed25519_key,
          flags: nil,
          data: <<0::8*32>>
        },
        %TorCert.Ed25519.Extension{
          type: :signed_with_ed25519_key,
          flags: :affects_validation,
          data: <<0::8*32>>
        }
      ],
      signature: <<0::8*64>>
    }

    assert TorCert.Ed25519.encode(cert) ==
             <<1>> <>
               <<0x04>> <>
               <<0::32>> <>
               <<1>> <>
               <<0::8*32>> <>
               <<2>> <>
               <<32::16>> <>
               <<0x04>> <>
               <<0>> <>
               <<0::8*32>> <>
               <<32::16>> <>
               <<0x04>> <>
               <<1>> <>
               <<0::8*32>> <>
               <<0::8*64>>
  end

  test "validates an Ed25519 certificate" do
    raw =
      <<1, 4, 0, 7, 33, 196, 1, 21, 195, 194, 141, 132, 50, 207, 113, 139, 70, 72, 23, 89, 84,
        174, 235, 255, 176, 47, 135, 165, 114, 166, 20, 243, 149, 223, 81, 221, 149, 34, 121, 1,
        0, 32, 4, 0, 194, 4, 162, 205, 242, 49, 217, 184, 187, 127, 147, 15, 211, 173, 83, 179,
        26, 111, 116, 63, 71, 28, 173, 15, 33, 128, 137, 199, 170, 24, 162, 214, 126, 87, 191,
        221, 228, 211, 40, 51, 76, 218, 59, 44, 246, 69, 128, 88, 202, 119, 149, 210, 218, 90,
        202, 93, 101, 175, 206, 140, 203, 91, 184, 175, 31, 33, 72, 63, 91, 196, 103, 40, 144,
        114, 231, 206, 29, 192, 53, 144, 214, 70, 133, 170, 155, 176, 21, 31, 30, 86, 51, 140,
        142, 132, 60, 4>>

    cert = TorCert.Ed25519.decode(raw)

    assert TorCert.Ed25519.is_valid?(cert, hd(cert.extensions).data, ~U[2023-04-27 00:00:00Z])
  end

  test "validates an invalid Ed25519 certificate" do
    raw =
      <<1, 4, 0, 7, 33, 196, 1, 21, 195, 194, 141, 132, 50, 207, 113, 139, 70, 72, 23, 89, 84,
        174, 235, 255, 176, 47, 135, 165, 114, 166, 20, 243, 149, 223, 81, 221, 149, 34, 121, 1,
        0, 32, 4, 0, 194, 4, 162, 205, 242, 49, 217, 184, 187, 127, 147, 15, 211, 173, 83, 179,
        26, 111, 116, 63, 71, 28, 173, 15, 33, 128, 137, 199, 170, 24, 162, 214, 126, 87, 191,
        221, 228, 211, 40, 51, 76, 218, 59, 44, 246, 69, 128, 88, 202, 119, 149, 210, 218, 90,
        202, 93, 101, 175, 206, 140, 203, 91, 184, 175, 31, 33, 72, 63, 91, 196, 103, 40, 144,
        114, 231, 206, 29, 192, 53, 144, 214, 70, 133, 170, 155, 176, 21, 31, 30, 86, 51, 140,
        142, 132, 60, 69>>

    cert = TorCert.Ed25519.decode(raw)

    assert !TorCert.Ed25519.is_valid?(cert, hd(cert.extensions).data, ~U[2023-04-27 00:00:00Z])
  end

  test "validates an expired Ed25519 certificate" do
    raw =
      <<1, 4, 0, 7, 33, 196, 1, 21, 195, 194, 141, 132, 50, 207, 113, 139, 70, 72, 23, 89, 84,
        174, 235, 255, 176, 47, 135, 165, 114, 166, 20, 243, 149, 223, 81, 221, 149, 34, 121, 1,
        0, 32, 4, 0, 194, 4, 162, 205, 242, 49, 217, 184, 187, 127, 147, 15, 211, 173, 83, 179,
        26, 111, 116, 63, 71, 28, 173, 15, 33, 128, 137, 199, 170, 24, 162, 214, 126, 87, 191,
        221, 228, 211, 40, 51, 76, 218, 59, 44, 246, 69, 128, 88, 202, 119, 149, 210, 218, 90,
        202, 93, 101, 175, 206, 140, 203, 91, 184, 175, 31, 33, 72, 63, 91, 196, 103, 40, 144,
        114, 231, 206, 29, 192, 53, 144, 214, 70, 133, 170, 155, 176, 21, 31, 30, 86, 51, 140,
        142, 132, 60, 4>>

    cert = TorCert.Ed25519.decode(raw)

    assert !TorCert.Ed25519.is_valid?(cert, hd(cert.extensions).data, ~U[2023-04-27 21:00:00Z])
  end
end
