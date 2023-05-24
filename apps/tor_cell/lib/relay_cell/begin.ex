# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell.Begin do
  defstruct host: nil,
            port: nil,
            flags: nil

  @doc """
  Decodes the data of a RELAY_BEGIN TorCell into its internal representation.

  Returns a TorCell.RelayCell.Begin.
  """
  def decode(data) do
    [addrport, <<flags::32>>] = :binary.split(data, <<0>>)

    # TODO: Validate host
    # TODO: Convert host into octet
    %{host: host, path: "", port: port, scheme: "kludge"} =
      :uri_string.parse("kludge://" <> addrport)

    flags = %{
      # TODO: Make this less redundant
      ipv6_okay: Bitwise.band(Bitwise.bsr(flags, 0), 1) == 1,
      ipv4_not_okay: Bitwise.band(Bitwise.bsr(flags, 1), 1) == 1,
      ipv6_preferred: Bitwise.band(Bitwise.bsr(flags, 2), 1) == 1
    }

    %TorCell.RelayCell.Begin{
      host: host,
      port: port,
      flags: flags
    }
  end

  # TODO: Write documentation
  def encode(cell) do
    flags = 0

    # TODO: Make this less redundant
    flags =
      if cell.flags.ipv6_okay do
        Bitwise.bor(flags, 1)
      else
        flags
      end

    flags =
      if cell.flags.ipv4_not_okay do
        Bitwise.bor(flags, 2)
      else
        flags
      end

    flags =
      if cell.flags.ipv6_preferred do
        Bitwise.bor(flags, 4)
      else
        flags
      end

    cell.host <> ":" <> Integer.to_string(cell.port) <> <<0>> <> <<flags::32>>
  end
end
