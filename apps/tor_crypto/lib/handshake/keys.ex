# SPDX-License-Identifier: ISC

defmodule TorCrypto.Handshake.Keys do
  @enforce_keys [:df, :db, :kf, :kb]
  defstruct df: nil,
            db: nil,
            kf: nil,
            kb: nil

  @type t :: %TorCrypto.Handshake.Keys{
          df: TorCrypto.Digest.t(),
          db: TorCrypto.Digest.t(),
          kf: TorCrypto.OnionStream.t(),
          kb: TorCrypto.OnionStream.t()
        }
end
