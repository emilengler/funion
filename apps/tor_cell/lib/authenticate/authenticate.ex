# SPDX-License-Identifier: ISC

defmodule TorCell.Authenticate do
  @enforce_keys [:auth_type, :authentication]
  defstruct auth_type: nil,
            authentication: nil

  @type t :: %TorCell.Authenticate{auth_type: auth_type(), authentication: authentication()}
  @type auth_type :: :ed25519_sha256_rfc5705
  @type authentication :: TorCell.Authenticate.Ed25519Sha256Rfc5705.t()

  @spec decode(binary()) :: t()
  def decode(payload) do
    remaining = payload
    <<3::16, remaining::binary>> = remaining
    <<auth_len::16, remaining::binary>> = remaining
    <<authentication::binary-size(auth_len), _::binary>> = remaining

    %TorCell.Authenticate{
      auth_type: :ed25519_sha256_rfc5705,
      authentication: TorCell.Authenticate.Ed25519Sha256Rfc5705.decode(authentication)
    }
  end

  @spec encode(t()) :: binary()
  def encode(cell) do
    :ed25519_sha256_rfc5705 = cell.auth_type
    authentication = TorCell.Authenticate.Ed25519Sha256Rfc5705.encode(cell.authentication)

    <<3::16, byte_size(authentication)::16>> <> authentication
  end
end
