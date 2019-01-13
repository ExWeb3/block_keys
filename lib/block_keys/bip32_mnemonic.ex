defmodule BlockKeys.Bip32Mnemonic do
  def generate do
    entropy = SecureRandom.random_bytes(32)

    checksum = 
      entropy
      |> entropy_hash
      |> extract_checksum

    seed = entropy <> << checksum >> 

    sequences(seed, [])
    |> to_mnemonic(words())
  end

  def sequences(<< seq :: size(11), rest :: bitstring >>, output) do
    sequences(rest, [seq] ++ output)
  end
  def sequences(<<>>, output), do: output

  def entropy_hash(sequence) do
    sequence 
    |> :libsecp256k1.sha256
  end

  def extract_checksum(<< checksum :: size(8), bits :: bitstring >>) do
    checksum
  end

  def chunk_bits(binary, n) do
    for << chunk::size(n) <- binary >>, do: <<chunk::size(n)>>
  end

  def words do
    "./assets/english.txt"
    |> File.stream!
    |> Stream.map(&String.trim/1)
    |> Enum.to_list
    |> List.to_tuple
  end

  def to_mnemonic(sequences, words) do
    sequences
    |> Enum.map(fn seq ->
      words
      |> Kernel.elem(seq)
    end)
  end
end
