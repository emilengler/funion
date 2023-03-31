defmodule TorCertEd25519Test do
  use ExUnit.Case
  doctest TorCert.Ed25519

  test "fetches a TorCert.Ed25519" do
    extensions =
      <<32::16>> <>
        <<0x04::8>> <>
        <<0::8>> <>
        <<0::32*8>> <>
        <<32::16>> <>
        <<0x04::8>> <>
        <<1::8>> <>
        <<0::32*8>>

    data =
      <<1::8>> <>
        <<0x04::8>> <>
        <<0::32>> <>
        <<1::8>> <>
        <<0::32*8>> <>
        <<2::8>> <>
        extensions <>
        <<0::128*8>>

    {cert, data} = TorCert.Ed25519.fetch(data)

    assert cert == %TorCert.Ed25519{
             cert_type: :ed25519_signing_id,
             expiration_date: DateTime.from_unix!(0),
             cert_key_type: :ed25519,
             certified_key: <<0::32*8>>,
             extensions: [
               %TorCert.Ed25519.Extension{
                 type: :signed_with_ed25519_key,
                 flags: nil,
                 data: <<0::32*8>>
               },
               %TorCert.Ed25519.Extension{
                 type: :signed_with_ed25519_key,
                 flags: :affects_validation,
                 data: <<0::32*8>>
               }
             ],
             signature: <<0::64*8>>
           }

    assert data == <<0::64*8>>
  end

  test "encodes a TorCert.Ed25519" do
    cert = %TorCert.Ed25519{
      cert_type: :ed25519_signing_id,
      expiration_date: DateTime.from_unix!(0),
      cert_key_type: :ed25519,
      certified_key: <<0::32*8>>,
      extensions: [
        %TorCert.Ed25519.Extension{
          type: :signed_with_ed25519_key,
          flags: nil,
          data: <<0::32*8>>
        },
        %TorCert.Ed25519.Extension{
          type: :signed_with_ed25519_key,
          flags: :affects_validation,
          data: <<0::32*8>>
        }
      ],
      signature: <<0::64*8>>
    }

    assert TorCert.Ed25519.encode(cert) ==
             <<1::8>> <>
               <<0x04::8>> <>
               <<0::32>> <>
               <<1::8>> <>
               <<0::32*8>> <>
               <<2::8>> <>
               <<32::16>> <>
               <<0x04::8>> <>
               <<0::8>> <>
               <<0::32*8>> <>
               <<32::16>> <>
               <<0x04::8>> <>
               <<1::8>> <>
               <<0::32*8>> <>
               <<0::64*8>>
  end
end
