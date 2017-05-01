module Main where
import TPMUtil

takeMain = takeInit

main :: IO ()
main = do k <- takeInit;
          return ();
