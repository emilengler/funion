defmodule TorCell do
  @moduledoc """
  Provides features for handling with various Tor Cells.
  """
  defstruct circ_id: nil,
            cmd: nil,
            payload: nil

  defp decode_cmd(cmd) do
    case cmd do
      0 -> :padding
      7 -> :versions
      8 -> :netinfo
      10 -> :create2
      11 -> :created2
      128 -> :vpadding
      129 -> :certs
      130 -> :auth_challenge
      131 -> :authenticate
    end
  end

  defp encode_circ_id_len(circ_id, circ_id_len) do
    # Convet circ_id_len from bytes to bits
    circ_id_len = circ_id_len * 8

    <<circ_id::integer-size(circ_id_len)>>
  end

  defp encode_cmd(cmd) do
    case cmd do
      :padding -> <<0>>
      :versions -> <<7>>
      :netinfo -> <<8>>
      :create2 -> <<10>>
      :created2 -> <<11>>
      :vpadding -> <<128>>
      :certs -> <<129>>
      :auth_challenge -> <<130>>
      :authenticate -> <<131>>
    end
  end

  defp encode_payload(payload, cmd) do
    payload =
      case cmd do
        :padding -> TorCell.Padding.encode(payload)
        :versions -> TorCell.Versions.encode(payload)
        :netinfo -> TorCell.Netinfo.encode(payload)
        :create2 -> TorCell.Create2.encode(payload)
        :created2 -> TorCell.Created2.encode(payload)
        :vpadding -> TorCell.Vpadding.encode(payload)
        :certs -> TorCell.Certs.encode(payload)
        :auth_challenge -> TorCell.AuthChallenge.encode(payload)
        :authenticate -> TorCell.Authenticate.encode(payload)
      end

    # Fill the payload with padding bytes
    # TODO: Consider doing this in the TorCell.XXX.encode() functions
    payload =
      if !is_vlen?(cmd) do
        padding = 509 - byte_size(payload)
        payload <> <<0::padding*8>>
      else
        payload
      end

    if is_vlen?(cmd) do
      <<byte_size(payload)::16>> <> payload
    else
      payload
    end
  end

  defp fetch_circ_id(data, circ_id_len) do
    # Convert circ_id_len from bytes to bits
    circ_id_len = circ_id_len * 8

    <<circ_id::integer-size(circ_id_len), data::binary>> = data
    {circ_id, data}
  end

  defp fetch_payload(data, cmd) do
    # TODO: Consider splitting this into two functions
    {payload, data} =
      if is_vlen?(cmd) do
        <<length::16, data::binary>> = data
        <<payload::binary-size(length), data::binary>> = data
        {payload, data}
      else
        <<payload::binary-size(509), data::binary>> = data
        {payload, data}
      end

    payload =
      case cmd do
        :padding -> TorCell.Padding.decode(payload)
        :versions -> TorCell.Versions.decode(payload)
        :netinfo -> TorCell.Netinfo.decode(payload)
        :create2 -> TorCell.Create2.decode(payload)
        :created2 -> Torcell.Created2.decode(payload)
        :vpadding -> TorCell.Vpadding.decode(payload)
        :certs -> TorCell.Certs.decode(payload)
        :auth_challenge -> TorCell.AuthChallenge.decode(payload)
        :authenticate -> TorCell.Authenticate.decode(payload)
      end

    {payload, data}
  end

  defp is_vlen?(cmd) do
    cmd in [:versions, :vpadding, :certs, :auth_challenge, :authenticate]
  end

  @doc """
  Fetches the first TorCell in a binary.

  Returns the internal representation of the found TorCell, alongside
  the remaining data.
  """
  def fetch(data, circ_id_len \\ 4) do
    {circ_id, data} = fetch_circ_id(data, circ_id_len)
    <<cmd, data::binary>> = data
    cmd = decode_cmd(cmd)
    {payload, data} = fetch_payload(data, cmd)

    {
      %TorCell{
        circ_id: circ_id,
        cmd: cmd,
        payload: payload
      },
      data
    }
  end

  @doc """
  Encodes the TorCell into a binary.

  Returns a binary corresponding to the TorCell.
  """
  def encode(cell, circ_id_len \\ 4) do
    encode_circ_id_len(cell.circ_id, circ_id_len) <>
      encode_cmd(cell.cmd) <>
      encode_payload(cell.payload, cell.cmd)
  end
end
