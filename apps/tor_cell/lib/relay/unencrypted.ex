defmodule TorCell.Relay.Unencrypted do
  defstruct cmd: nil,
            stream_id: nil,
            payload: nil,
            padding: nil

  defp decode_cmd(cmd) do
    case cmd do
      1 -> :relay_begin
      2 -> :relay_data
      3 -> :relay_end
      4 -> :relay_connected
      5 -> :relay_sendme
      6 -> :relay_extend
      7 -> :relay_extended
      8 -> :relay_truncate
      9 -> :relay_truncated
      10 -> :relay_drop
      11 -> :relay_resolve
      12 -> :relay_resolved
      13 -> :relay_begin_dir
      14 -> :relay_extend2
      15 -> :relay_extended2
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

    padding_len = 509 - 11 - length
    <<padding::binary-size(padding_len), _::binary>> = data

    %TorCell.Relay.Unencrypted{
      cmd: cmd,
      stream_id: stream_id,
      payload: payload,
      padding: padding
    }
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
end
