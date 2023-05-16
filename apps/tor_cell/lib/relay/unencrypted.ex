defmodule TorCell.Relay.Unencrypted do
  defstruct cmd: nil,
            stream_id: nil,
            payload: nil,
            padding: nil

  defp decode_cmd(cmd) do
    case cmd do
      1 -> :relay_begin
      4 -> :relay_connected
    end
  end

  defp decode(data) do
    <<cmd, data::binary>> = data
    cmd = decode_cmd(cmd)
    <<_::16, data::binary>> = data
    <<stream_id::16, data::binary>> = data
    <<_::32, data::binary>> = data
    <<length::16, data::binary>> = data
    <<payload::binary-size(length), data::binary>> = data

    payload =
      case cmd do
        :relay_begin -> TorCell.Relay.Begin.decode(payload)
        :relay_connected -> TorCell.Relay.Connected.decode(payload)
      end

    padding_len = 509 - 11 - length
    <<padding::binary-size(padding_len), _::binary>> = data

    %TorCell.Relay.Unencrypted{
      cmd: cmd,
      stream_id: stream_id,
      payload: payload,
      padding: padding
    }
  end

  defp encode_cmd(cmd) do
    case cmd do
      :relay_begin -> <<1>>
      :relay_connected -> <<4>>
    end
  end

  defp encode_payload(cmd, payload) do
    case cmd do
      :relay_begin -> TorCell.Relay.Begin.encode(payload)
      :relay_connected -> TorCell.Relay.Connected.encode(payload)
    end
  end

  defp encode(cell) do
    cmd = encode_cmd(cell.cmd)
    payload = encode_payload(cell.cmd, cell.payload)

    encoded =
      cmd <>
        <<1::16>> <> <<cell.stream_id::16>> <> <<0::32>> <> <<byte_size(payload)::16>> <> payload

    # Add the padding
    padding_length = 509 - 11 - byte_size(payload)
    encoded <> <<0::integer-size(padding_length)-unit(8)>>
  end

  defp is_decrypted?(data, our_digest) do
    <<_, remainder::binary>> = data
    <<recognized::16, remainder::binary>> = remainder
    <<_::16, remainder::binary>> = remainder
    <<their_digest::32, _::binary>> = remainder

    # Replace the digest field in data with four zeros
    <<data_prefix::binary-size(5), data_suffix::binary>> = data
    <<_::binary-size(4), data_suffix::binary>> = data_suffix
    data = data_prefix <> <<0::32>> <> data_suffix

    our_digest = TorCrypto.Digest.update(our_digest, data)
    <<our_digest::32>> = TorCrypto.Digest.calculate(our_digest)

    recognized == 0 && their_digest == our_digest
  end

  @doc """
  Decrypts a RELAY TorCell by removing length(keys) onion layers from it.

  Returns a tuple containing a {true, %TorCell.Relay.Unencrypted} if all onion
  skins could have been removed successfully or a {false, %TorCell.Relay} if
  it could not be fully decrypted.
  """
  def decrypt(cell, keys, digest) do
    data = TorCrypto.OnionSkin.decrypt(cell.onion_skin, keys)

    if is_decrypted?(data, digest) do
      {
        true,
        decode(data)
      }
    else
      {
        false,
        TorCell.Relay.encode(data)
      }
    end
  end

  @doc """
  Encodes an unencrypted RELAY TorCell into its internal representation, adding
  length(keys) onion layers to it.

  Returns a binary corresponding to the encoded and optionally encrypted TorCell.
  """
  def encrypt(cell, keys) do
    TorCell.Relay.decode(TorCrypto.OnionSkin.encrypt(encode(cell), keys))
  end
end
