import { Box, Text, styled } from '@ignite-ui/react'

export const Form = styled(Box, {
  marginTop: '$4',
  padding: '$4',

  display: 'grid',
  gridTemplateColumns: '1fr auto',
  gap: '$2',

  '@media (max-width: 600px)': {
    gridTemplateColumns: '1fr',
  },
})

export const FormAnnotation = styled(Text, {
  marginTop: '$2',
})
