# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Begin do
  @enforce_keys [:host, :port]
  defstruct host: nil,
            port: nil

  @type t :: %TorCell.RelayCell.Begin{host: String.t(), port: integer()}

  @spec decode(binary()) :: t()
  def decode(data) do
    [addrport, <<_::32>>] = :binary.split(data, <<0>>)

    # TODO: Validate host
    %{host: host, path: "", port: port, scheme: "kludge"} =
      :uri_string.parse("kludge://" <> addrport)

    %TorCell.RelayCell.Begin{host: host, port: port}
  end

  @spec encode(t()) :: binary()
  def encode(cell) do
    # Currently, the flags are static: IPv6 okay and IPv6 preferred
    flags = 5

    cell.host <> ":" <> Integer.to_string(cell.port) <> <<0, flags::32>>
  end
end
