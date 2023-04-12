defmodule TorCellAuthenticate do
  use ExUnit.Case
  doctest TorCell.Authenticate

  test "decodes a TorCell.Authenticate with RsaSha256Tlssecret" do
    auth =
      "AUTH0001" <>
        <<0::8*32>> <>
        <<1::8*32>> <>
        <<2::8*32>> <> <<3::8*32>> <> <<4::8*32>> <> <<5::8*32>> <> <<6::8*24>> <> <<42, 69>>

    payload = <<1::16>> <> <<byte_size(auth)::16>> <> auth
    cell = TorCell.Authenticate.decode(payload)

    assert cell == %TorCell.Authenticate{
             type: :rsa_sha256_tlssecret,
             auth: %TorCell.Authenticate.RsaSha256Tlssecret{
               cid: <<0::8*32>>,
               sid: <<1::8*32>>,
               slog: <<2::8*32>>,
               clog: <<3::8*32>>,
               scert: <<4::8*32>>,
               tlssecrets: <<5::8*32>>,
               rand: <<6::8*24>>,
               sig: <<42, 69>>
             }
           }
  end

  test "decodes a TorCell.Authenticate.Ed25519Sha256Rfc5705" do
    auth =
      "AUTH0003" <>
        <<0::8*32>> <>
        <<1::8*32>> <>
        <<2::8*32>> <>
        <<3::8*32>> <>
        <<4::8*32>> <>
        <<5::8*32>> <>
        <<6::8*32>> <>
        <<7::8*32>> <>
        <<8::8*24>> <>
        <<42, 69>>

    payload = <<3::16>> <> <<byte_size(auth)::16>> <> auth
    cell = TorCell.Authenticate.decode(payload)

    assert cell.type == :ed25519_sha256_rfc5705

    assert cell == %TorCell.Authenticate{
             type: :ed25519_sha256_rfc5705,
             auth: %TorCell.Authenticate.Ed25519Sha256Rfc5705{
               cid: <<0::8*32>>,
               sid: <<1::8*32>>,
               cid_ed: <<2::8*32>>,
               sid_ed: <<3::8*32>>,
               slog: <<4::8*32>>,
               clog: <<5::8*32>>,
               scert: <<6::8*32>>,
               tlssecrets: <<7::8*32>>,
               rand: <<8::8*24>>,
               sig: <<42, 69>>
             }
           }
  end

  test "encodes a TorCell.Authenticate.RsaSha256Tlssecret" do
    auth = %TorCell.Authenticate{
      type: :rsa_sha256_tlssecret,
      auth: %TorCell.Authenticate.RsaSha256Tlssecret{
        cid: <<0::8*32>>,
        sid: <<1::8*32>>,
        slog: <<2::8*32>>,
        clog: <<3::8*32>>,
        scert: <<4::8*32>>,
        tlssecrets: <<5::8*32>>,
        rand: <<6::8*24>>,
        sig: <<42, 69>>
      }
    }

    auth_payload =
      "AUTH0001" <>
        <<0::8*32>> <>
        <<1::8*32>> <>
        <<2::8*32>> <>
        <<3::8*32>> <> <<4::8*32>> <> <<5::8*32>> <> <<6::8*24>> <> <<42, 69>>

    assert TorCell.Authenticate.encode(auth) ==
             <<1::16>> <> <<byte_size(auth_payload)::16>> <> auth_payload
  end

  test "encodes a TorCell.Authenticate.Ed25519Sha256Rfc5705" do
    auth = %TorCell.Authenticate{
      type: :ed25519_sha256_rfc5705,
      auth: %TorCell.Authenticate.Ed25519Sha256Rfc5705{
        cid: <<0::8*32>>,
        sid: <<1::8*32>>,
        cid_ed: <<2::8*32>>,
        sid_ed: <<3::8*32>>,
        slog: <<4::8*32>>,
        clog: <<5::8*32>>,
        scert: <<6::8*32>>,
        tlssecrets: <<7::8*32>>,
        rand: <<8::8*24>>,
        sig: <<42, 69>>
      }
    }

    auth_payload =
      "AUTH0003" <>
        <<0::8*32>> <>
        <<1::8*32>> <>
        <<2::8*32>> <>
        <<3::8*32>> <>
        <<4::8*32>> <>
        <<5::8*32>> <>
        <<6::8*32>> <>
        <<7::8*32>> <>
        <<8::8*24>> <>
        <<42, 69>>

    assert TorCell.Authenticate.encode(auth) ==
             <<3::16>> <> <<byte_size(auth_payload)::16>> <> auth_payload
  end
end
