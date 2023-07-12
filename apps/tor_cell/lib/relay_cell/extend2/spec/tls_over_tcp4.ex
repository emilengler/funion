# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Extend2.Spec.TlsOverTcp4 do
  @enforce_keys [:ip, :port]
  defstruct ip: nil,
            port: nil

  @type t :: %TorCell.RelayCell.Extend2.Spec.TlsOverTcp4{ip: tuple(), port: integer()}

  @spec decode(binary()) :: TorCell.RelayCell.Extend2.Spec.TlsOverTcp4
  def decode(spec) do
    remaining = spec
    <<ip::binary-size(4), remaining::binary>> = remaining
    <<port::16, _::binary>> = remaining
    ip = List.to_tuple(:binary.bin_to_list(ip))

    %TorCell.RelayCell.Extend2.Spec.TlsOverTcp4{ip: ip, port: port}
  end

  @spec encode(TorCell.RelayCell.Extend2.Spec.TlsOverTcp4) :: binary()
  def encode(spec) do
    :binary.list_to_bin(Tuple.to_list(spec.ip)) <> <<spec.port::16>>
  end
end
