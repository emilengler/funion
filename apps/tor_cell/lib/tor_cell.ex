# SPDX-License-Identifier: ISC

defmodule TorCell do
  @moduledoc """
  An implementation of the cells found within `tor-spec.txt`.
  """
  @enforce_keys [:circ_id, :cmd, :payload]
  defstruct circ_id: nil,
            cmd: nil,
            payload: nil

  @type t :: %TorCell{circ_id: circ_id(), cmd: cmd(), payload: payload()}
  @type circ_id :: integer()
  @type cmd :: :padding | :versions | :vpadding
  @type payload :: TorCell.Padding | TorCell.Versions | TorCell.Vpadding

  @spec fetch_circ_id(binary(), integer()) :: {circ_id(), binary()}
  defp fetch_circ_id(data, circ_id_len) do
    <<circ_id::integer-size(circ_id_len)-unit(8), remaining::binary>> = data
    {circ_id, remaining}
  end

  @spec fetch_cmd(binary()) :: {cmd(), binary()}
  defp fetch_cmd(data) do
    <<cmd, remaining::binary>> = data

    cmd =
      case cmd do
        0 -> :padding
        7 -> :versions
        128 -> :vpadding
      end

    {cmd, remaining}
  end

  @spec fetch_payload(binary(), cmd()) :: {payload(), binary()}
  defp fetch_payload(data, cmd) do
    {payload, remaining} =
      if is_vlen?(cmd) do
        remaining = data
        <<len::16, remaining::binary>> = remaining
        <<payload::binary-size(len), remaining::binary>> = remaining
        {payload, remaining}
      else
        remaining = data
        <<payload::binary-size(509), remaining::binary>> = remaining
        {payload, remaining}
      end

    payload =
      case cmd do
        :padding -> TorCell.Padding.decode(payload)
        :versions -> TorCell.Versions.decode(payload)
        :vpadding -> TorCell.Vpadding.decode(payload)
      end

    {payload, remaining}
  end

  @spec encode_circ_id(circ_id(), integer()) :: binary()
  defp encode_circ_id(circ_id, circ_id_len) do
    <<circ_id::integer-size(circ_id_len)-unit(8)>>
  end

  @spec encode_cmd(cmd()) :: binary()
  defp encode_cmd(cmd) do
    case cmd do
      :padding -> <<0>>
      :versions -> <<7>>
      :vpadding -> <<128>>
    end
  end

  @spec encode_payload(payload(), cmd()) :: binary()
  defp encode_payload(payload, cmd) do
    payload =
      case cmd do
        :padding -> TorCell.Padding.encode(payload)
        :versions -> TorCell.Versions.encode(payload)
        :vpadding -> TorCell.Vpadding.encode(payload)
      end

    # Some final adjustments
    if is_vlen?(cmd) do
      # Add length
      <<byte_size(payload)::16>> <> payload
    else
      # Fill with padding bytes
      padding = 509 - byte_size(payload)
      payload <> <<0::padding*8>>
    end
  end

  @spec is_vlen?(cmd()) :: boolean()
  defp is_vlen?(cmd) do
    cmd in [:versions, :vpadding]
  end

  @doc """
  Fetches the first cell found within a binary.

  Returns the decoded cell alongside a binary with the remaining data
  """
  @spec fetch(binary(), integer()) :: {TorCell, binary()}
  def fetch(data, circ_id_len \\ 4) do
    remaining = data
    {circ_id, remaining} = fetch_circ_id(remaining, circ_id_len)
    {cmd, remaining} = fetch_cmd(remaining)
    {payload, remaining} = fetch_payload(remaining, cmd)

    {
      %TorCell{
        circ_id: circ_id,
        cmd: cmd,
        payload: payload
      },
      remaining
    }
  end

  @doc """
  Encodes a TorCell into a binary.
  """
  @spec encode(TorCell, integer()) :: binary()
  def encode(cell, circ_id_len \\ 4) do
    encode_circ_id(cell.circ_id, circ_id_len) <>
      encode_cmd(cell.cmd) <>
      encode_payload(cell.payload, cell.cmd)
  end
end
