defmodule TorCell.Authenticate.Ed25519Sha256Rfc5705 do
  defstruct cid: nil,
            sid: nil,
            cid_ed: nil,
            sid_ed: nil,
            slog: nil,
            clog: nil,
            scert: nil,
            tlssecrets: nil,
            rand: nil,
            sig: nil

  @doc """
  Decodes the payload of the Authentication field inside an AUTHENTICATE
  TorCell into its internal representation.

  Returns a TorCell.Authenticate.Ed25519Sha256Rfc5705 with the fields being
  set accordingly.
  """
  def decode(payload) do
    # Skip the AUTH0003
    # TODO: Validate the AUTH0003
    <<_::binary-size(8), payload::binary>> = payload
    <<cid::binary-size(32), payload::binary>> = payload
    <<sid::binary-size(32), payload::binary>> = payload
    <<cid_ed::binary-size(32), payload::binary>> = payload
    <<sid_ed::binary-size(32), payload::binary>> = payload
    <<slog::binary-size(32), payload::binary>> = payload
    <<clog::binary-size(32), payload::binary>> = payload
    <<scert::binary-size(32), payload::binary>> = payload
    <<tlssecrets::binary-size(32), payload::binary>> = payload
    <<rand::binary-size(24), payload::binary>> = payload
    # The remaining payload is considered to be the sig

    %TorCell.Authenticate.Ed25519Sha256Rfc5075{
      cid: cid,
      sid: sid,
      cid_ed: cid_ed,
      sid_ed: sid_ed,
      slog: slog,
      clog: clog,
      scert: scert,
      tlssecrets: tlssecrets,
      rand: rand,
      sig: payload
    }
  end

  @doc """
  Encodes a TorCell.Authenticate.Ed25519Sha256Rfc5705 into a binary.

  Returns a binary corresponding to the binary representation of an
  authentication, as found within the AUTHENTICATE TorCell.
  """
  def encode(auth) do
    "AUTH0003" <>
      <<auth.cid::binary-size(32)>> <>
      <<auth.sid::binary-size(32)>> <>
      <<auth.cid_ed::binary-size(32)>> <>
      <<auth.sid_ed::binary-size(32)>> <>
      <<auth.slog::binary-size(32)>> <>
      <<auth.clog::binary-size(32)>> <>
      <<auth.scert::binary-size(32)>> <>
      <<auth.tlssecrets::binary-size(32)>> <>
      <<auth.rand::binary-size(24)>> <>
      <<auth.sig>>
  end
end
