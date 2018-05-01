import System.IO

sumFileAvg :: IO Float
sumFileAvg = do
  fString <- readFile "temp.txt"
  let vals = lines fString
      numVals = map readInt vals
      vsum = sum numVals
  return (vsum / (fromIntegral (length vals)))
  where
    readInt = read :: String -> Float

