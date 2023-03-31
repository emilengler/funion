defmodule TorCertEd25519ExtensionTest do
  use ExUnit.Case
  doctest TorCert.Ed25519.Extension

  test "fetches a TorCert.Ed25519.Extension" do
    data = <<32::16>> <> <<0x04::8>> <> <<0::8>> <> <<0::32*8>>
    {ext, data} = TorCert.Ed25519.Extension.fetch(data)

    assert ext == %TorCert.Ed25519.Extension{
             type: :signed_with_ed25519_key,
             flags: nil,
             data: <<0::32*8>>
           }

    assert data == <<>>
  end

  test "fetches a TorCert.Ed25519.Extension with remaining data" do
    data = <<32::16>> <> <<0x04::8>> <> <<1::8>> <> <<0::64*8>>
    {ext, data} = TorCert.Ed25519.Extension.fetch(data)

    assert ext == %TorCert.Ed25519.Extension{
             type: :signed_with_ed25519_key,
             flags: :affects_validation,
             data: <<0::32*8>>
           }

    assert data == <<0::32*8>>
  end

  test "encodes a TorCert.Ed25519.Extension (flags: nil)" do
    ext = %TorCert.Ed25519.Extension{
      type: :signed_with_ed25519_key,
      flags: nil,
      data: <<0::32*8>>
    }

    assert TorCert.Ed25519.Extension.encode(ext) ==
             <<32::16>> <> <<0x04::8>> <> <<0::8>> <> <<0::32*8>>
  end

  test "encodes a TorCert.Ed25519.Extension (flags: :affects_validation)" do
    ext = %TorCert.Ed25519.Extension{
      type: :signed_with_ed25519_key,
      flags: :affects_validation,
      data: <<0::32*8>>
    }

    assert TorCert.Ed25519.Extension.encode(ext) ==
             <<32::16>> <> <<0x04::8>> <> <<1::8>> <> <<0::32*8>>
  end
end
