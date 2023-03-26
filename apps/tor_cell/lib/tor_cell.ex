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
      1 -> :create
      2 -> :created
      3 -> :relay
      4 -> :destroy
      5 -> :create_fast
      6 -> :created_fast
      7 -> :versions
      8 -> :netinfo
      9 -> :relay_early
      10 -> :create2
      11 -> :created2
      12 -> :padding_negotiate
      128 -> :vpadding
      129 -> :certs
      130 -> :auth_challenge
      131 -> :authenticate
      132 -> :authorize
    end
  end

  defp encode_circ_id(circ_id, circ_id_len) do
    # Convert from bytes to bits
    circ_id_len = circ_id_len * 8

    # TODO: Catch overflow
    <<circ_id::integer-size(circ_id_len)>>
  end

  defp encode_cmd(cmd) do
    <<case cmd do
        :padding -> 0
        :create -> 1
        :created -> 2
        :relay -> 3
        :destroy -> 4
        :create_fast -> 5
        :created_fast -> 6
        :versions -> 7
        :netinfo -> 8
        :relay_early -> 9
        :create2 -> 10
        :created2 -> 11
        :padding_negotiate -> 12
        :vpadding -> 128
        :certs -> 129
        :auth_challenge -> 130
        :authenticate -> 131
        :authorize -> 132
      end::8>>
  end

  defp encode_payload(payload, vlen) do
    if vlen do
      # TODO: Check overflow
      <<byte_size(payload)::16>> <> payload
    else
      <<payload::binary-size(509)>>
    end
  end

  defp fetch_circ_id(data, circ_id_len) do
    # Convert from bytes to bits
    circ_id_len = circ_id_len * 8

    <<circ_id::integer-size(circ_id_len), data::binary>> = data
    {circ_id, data}
  end

  defp fetch_cmd(data) do
    <<cmd::8, data::binary>> = data
    {decode_cmd(cmd), data}
  end

  defp fetch_payload(data, vlen) do
    if vlen do
      <<length::16, data::binary>> = data
      <<payload::binary-size(length), data::binary>> = data
      {payload, data}
    else
      <<payload::binary-size(509), data::binary>> = data
      {payload, data}
    end
  end

  defp is_vlen?(cmd) do
    cmd in [:versions, :vpadding, :certs, :auth_challenge, :authenticate, :authorize]
  end

  @doc """
  Fetches the first Cell in a binary.

  Returns the internal representation of the found Cell, alongside the
  remaining data.
  """
  def fetch(data, circ_id_len \\ 4) do
    {circ_id, data} = fetch_circ_id(data, circ_id_len)
    {cmd, data} = fetch_cmd(data)
    {payload, data} = fetch_payload(data, is_vlen?(cmd))

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
  """
  def encode(cell, circ_id_len \\ 4) do
    encode_circ_id(cell.circ_id, circ_id_len) <>
      encode_cmd(cell.cmd) <>
      encode_payload(cell.payload, is_vlen?(cell.cmd))
  end
end
