# SPDX-License-Identifier: ISC

defmodule TorCell.AuthChallenge do
  @enforce_keys [:challenge, :methods]
  defstruct challenge: nil,
            methods: nil

  @type t :: %TorCell.AuthChallenge{challenge: binary(), methods: methods()}
  @type methods() :: list(method())
  @type method() :: :rsa_sha256_tlssecret | :ed25519_sha256_rfc5705

  @spec decode(binary()) :: t()
  def decode(payload) do
    remaining = payload
    <<challenge::binary-size(32), remaining::binary>> = remaining
    <<n_methods::16, remaining::binary>> = remaining
    <<methods::binary-size(2 * n_methods), _::binary>> = remaining

    methods = Enum.chunk_every(:binary.bin_to_list(methods), 2)

    methods =
      Enum.map(methods, fn bytes ->
        <<method::16>> = :binary.list_to_bin(bytes)

        case method do
          1 -> :rsa_sha256_tlssecret
          3 -> :ed25519_sha256_rfc5705
        end
      end)

    %TorCell.AuthChallenge{challenge: challenge, methods: methods}
  end

  @spec encode(t()) :: binary()
  def encode(cell) do
    methods =
      Enum.join(
        Enum.map(cell.methods, fn method ->
          case method do
            :rsa_sha256_tlssecret -> <<1::16>>
            :ed25519_sha256_rfc5705 -> <<3::16>>
          end
        end)
      )

    <<cell.challenge::binary-size(32), length(cell.methods)::16>> <> methods
  end
end
