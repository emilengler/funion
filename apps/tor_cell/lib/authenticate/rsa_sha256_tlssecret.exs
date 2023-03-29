defmodule TorCell.Authenticate.RsaSha256Tlssecret do
  defstruct cid: nil,
            sid: nil,
            slog: nil,
            clog: nil,
            scert: nil,
            tlssecrets: nil,
            rand: nil,
            sig: nil

  @doc """
  Decodes the payload of the Authentication field inside an AUTHENTICATE
  TorCell into its internal representation.

  Returns a TorCell.Authenticate.RsaSha256Tlssecret with the fields being
  set accordingly.
  """
  def decode(payload) do
    # Skip the AUTH0001
    # TODO: Validate the AUTH0001
    <<_::binary-size(8), payload::binary>> = payload
    <<cid::binary-size(32), payload::binary>> = payload
    <<sid::binary-size(32), payload::binary>> = payload
    <<slog::binary-size(32), payload::binary>> = payload
    <<clog::binary-size(32), payload::binary>> = payload
    <<scert::binary-size(32), payload::binary>> = payload
    <<tlssecrets::binary-size(32), payload::binary>> = payload
    <<rand::binary-size(24), payload::binary>> = payload
    # The remaining payload is considered to be the sig

    %TorCell.Authentication.RsaSha256Tlssecret{
      cid: cid,
      sid: sid,
      slog: slog,
      clog: clog,
      scert: scert,
      tlssecrets: tlssecrets,
      rand: rand,
      sig: payload
    }
  end

  @doc """
  Encodes a TorCell.Authenticate.RsaSha256Tlssecret into a binary.

  Returns a binary corresponding to the binary representation of an
  authentication, as found within the AUTHENTICATE TorCell.
  """
  def encode(auth) do
    "AUTH0001" <>
      <<auth.cid::binary-size(32)>> <>
      <<auth.sid::binary-size(32)>> <>
      <<auth.slog::binary-size(32)>> <>
      <<auth.clog::binary-size(32)>> <>
      <<auth.scert::binary-size(32)>> <>
      <<auth.tlssecrets::binary-size(32)>> <>
      <<auth.rand::binary-size(24)>>

    auth.sig
  end
end
