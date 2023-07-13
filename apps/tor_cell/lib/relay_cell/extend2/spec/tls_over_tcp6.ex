# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Extend2.Spec.TlsOverTcp6 do
  @enforce_keys [:ip, :port]
  defstruct ip: nil,
            port: nil

  @type t :: %TorCell.RelayCell.Extend2.Spec.TlsOverTcp6{ip: addr(), port: integer()}
  @type addr :: :inet.ip_address()

  @spec decode(binary()) :: t()
  def decode(spec) do
    remaining = spec
    <<ip::binary-size(16), remaining::binary>> = remaining
    <<port::16, _::binary>> = remaining
    ip = List.to_tuple(:binary.bin_to_list(ip))

    %TorCell.RelayCell.Extend2.Spec.TlsOverTcp6{ip: ip, port: port}
  end

  @spec encode(t()) :: binary()
  def encode(spec) do
    :binary.list_to_bin(Tuple.to_list(spec.ip)) <> <<spec.port::16>>
  end
end
