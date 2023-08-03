# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell do
  @enforce_keys [:cmd, :stream_id, :data]
  defstruct cmd: nil,
            stream_id: nil,
            data: nil

  @type t :: %TorCell.RelayCell{cmd: cmd(), stream_id: stream_id(), data: data()}
  @type cmd :: :begin | :data | :end | :connected | :extend2 | :extended2
  @type stream_id :: integer()
  @type data ::
          TorCell.RelayCell.Begin.t()
          | TorCell.RelayCell.Data.t()
          | TorCell.RelayCell.End.t()
          | TorCell.RelayCell.Connected.t()
          | TorCell.RelayCell.Extend2.t()
          | TorCell.RelayCell.Extended2.t()

  # TODO: Move those into TorCrypto
  @type onion_skin :: binary()
  @type streams :: list(TorCrypto.OnionStream.t())
  @type digest :: TorCrypto.Digest.t()

  @spec gen_padding(integer()) :: binary()
  defp gen_padding(padding_len) do
    if padding_len <= 4 do
      <<0::integer-size(padding_len)-unit(8)>>
    else
      padding_len = padding_len - 4
      <<0::32>> <> :crypto.strong_rand_bytes(padding_len)
    end
  end

  @spec modify_digest(binary(), binary()) :: binary()
  defp modify_digest(data, digest) do
    <<prefix::binary-size(5), suffix::binary>> = data
    <<_::binary-size(4), suffix::binary>> = suffix
    prefix <> digest <> suffix
  end

  @spec zeroize_digest(binary()) :: binary()
  defp zeroize_digest(data) do
    modify_digest(data, <<0::32>>)
  end

  @spec decode_cmd(integer()) :: cmd()
  defp decode_cmd(cmd) do
    case cmd do
      1 -> :begin
      2 -> :data
      3 -> :end
      4 -> :connected
      14 -> :extend2
      15 -> :extended2
    end
  end

  @spec decode_data(cmd(), binary()) :: data()
  defp decode_data(cmd, data) do
    case cmd do
      :begin -> TorCell.RelayCell.Begin.decode(data)
      :data -> TorCell.RelayCell.Data.decode(data)
      :end -> TorCell.RelayCell.End.decode(data)
      :connected -> TorCell.RelayCell.Connected.decode(data)
      :extend2 -> TorCell.RelayCell.Extend2.decode(data)
      :extended2 -> TorCell.RelayCell.Extended2.decode(data)
    end
  end

  @spec encode_cmd(cmd()) :: binary()
  defp encode_cmd(cmd) do
    case cmd do
      :begin -> <<1>>
      :data -> <<2>>
      :end -> <<3>>
      :connected -> <<4>>
      :extend2 -> <<14>>
      :extended2 -> <<15>>
    end
  end

  @spec encode_data(cmd(), data()) :: binary()
  defp encode_data(cmd, data) do
    case cmd do
      :begin -> TorCell.RelayCell.Begin.encode(data)
      :data -> TorCell.RelayCell.Data.encode(data)
      :end -> TorCell.RelayCell.End.encode(data)
      :connected -> TorCell.RelayCell.Connected.encode(data)
      :extend2 -> TorCell.RelayCell.Extend2.encode(data)
      :extended2 -> TorCell.RelayCell.Extended2.encode(data)
    end
  end

  @spec decode(onion_skin(), digest()) :: {boolean(), t() | onion_skin(), digest()}
  defp decode(payload, digest) do
    remaining = payload
    <<cmd, remaining::binary>> = remaining
    <<recognized::16, remaining::binary>> = remaining
    <<stream_id::16, remaining::binary>> = remaining
    <<dig::binary-size(4), remaining::binary>> = remaining
    <<length::16, remaining::binary>> = remaining
    <<data::binary-size(length), remaining::binary>> = remaining
    padding = remaining
    true = byte_size(padding) == 509 - 11 - length

    cmd = decode_cmd(cmd)
    data = decode_data(cmd, data)

    # The digest with this cell's payload but the digest field set to zero
    new_digest = TorCrypto.Digest.update(digest, zeroize_digest(payload))

    if recognized == 0 && <<TorCrypto.Digest.calculate(new_digest)::binary-size(4)>> == dig do
      {true, %TorCell.RelayCell{cmd: cmd, stream_id: stream_id, data: data}, new_digest}
    else
      {false, payload, digest}
    end
  end

  @spec encode(t(), digest()) :: {onion_skin(), digest()}
  defp encode(cell, digest) do
    encoded_data = encode_data(cell.cmd, cell.data)
    padding_len = 509 - 11 - byte_size(encoded_data)

    encoded =
      encode_cmd(cell.cmd) <>
        <<0::16, cell.stream_id::16, 0::32, byte_size(encoded_data)::16>> <>
        encoded_data <> gen_padding(padding_len)

    digest = TorCrypto.Digest.update(digest, encoded)
    encoded = modify_digest(encoded, <<TorCrypto.Digest.calculate(digest)::binary-size(4)>>)

    {encoded, digest}
  end

  @doc """
  Tries to decrypt an onion skin into a TorCell.RelayCell, by removing `length(streams)` layers.

  On success, it will return `{true, TorCell.RelayCell, new_digest}`.
  If not all onion skins could be removed, it will return `{false, new_payload, digest}`,
  with as much onion skins removed as possible.
  """
  @spec decrypt(onion_skin(), streams(), digest()) :: {boolean(), t() | onion_skin(), digest()}
  def decrypt(onion_skin, streams, digest) do
    decode(TorCrypto.OnionStream.decrypt(streams, onion_skin), digest)
  end

  @doc """
  Encrypts a TorCell.RelayCell into an onion skin.

  Returns the onion skin with the updated digest.
  """
  @spec encrypt(t(), streams(), digest()) :: {onion_skin(), digest()}
  def encrypt(cell, streams, digest) do
    {encoded, digest} = encode(cell, digest)
    {TorCrypto.OnionStream.encrypt(streams, encoded), digest}
  end
end
