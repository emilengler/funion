# SPDX-License-Identifier: ISC

defmodule TorCell.Authenticate.Ed25519Sha256Rfc5705 do
  @enforce_keys [:cid, :sid, :cid_ed, :sid_ed, :slog, :clog, :scert, :tlssecrets, :rand, :sig]
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

  @type t :: %TorCell.Authenticate.Ed25519Sha256Rfc5705{
          cid: binary(),
          sid: binary(),
          cid_ed: binary(),
          sid_ed: binary(),
          slog: binary(),
          clog: binary(),
          scert: binary(),
          tlssecrets: binary(),
          rand: binary(),
          sig: binary()
        }

  @spec decode(binary()) :: TorCell.Authenticate.Ed25519Sha256Rfc5705
  def decode(payload) do
    remaining = payload
    <<"AUTH0003", remaining::binary>> = remaining
    <<cid::binary-size(32), remaining::binary>> = remaining
    <<sid::binary-size(32), remaining::binary>> = remaining
    <<cid_ed::binary-size(32), remaining::binary>> = remaining
    <<sid_ed::binary-size(32), remaining::binary>> = remaining
    <<slog::binary-size(32), remaining::binary>> = remaining
    <<clog::binary-size(32), remaining::binary>> = remaining
    <<scert::binary-size(32), remaining::binary>> = remaining
    <<tlssecrets::binary-size(32), remaining::binary>> = remaining
    <<rand::binary-size(24), remaining::binary>> = remaining
    sig = remaining

    %TorCell.Authenticate.Ed25519Sha256Rfc5705{
      cid: cid,
      sid: sid,
      cid_ed: cid_ed,
      sid_ed: sid_ed,
      slog: slog,
      clog: clog,
      scert: scert,
      tlssecrets: tlssecrets,
      rand: rand,
      sig: sig
    }
  end

  @spec encode(TorCell.Authenticate.Ed25519Sha256Rfc5705) :: binary()
  def encode(auth) do
    <<"AUTH0003", auth.cid::binary-size(32), auth.sid::binary-size(32),
      auth.cid_ed::binary-size(32), auth.sid_ed::binary-size(32), auth.slog::binary-size(32),
      auth.clog::binary-size(32), auth.scert::binary-size(32), auth.tlssecrets::binary-size(32),
      auth.rand::binary-size(24)>> <> auth.sig
  end
end
